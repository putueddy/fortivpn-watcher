package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

/* =========  JSON LOGGING  ========= */

type logEntry struct {
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Timestamp string         `json:"ts"`
	Fields    map[string]any `json:"fields,omitempty"`
}

func jsonLog(level, msg string, fields map[string]any) {
	e := logEntry{
		Level:     level,
		Message:   msg,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Fields:    fields,
	}
	b, _ := json.Marshal(e)
	os.Stdout.Write(append(b, '\n'))
}

/* =========  MODEL  ========= */

type VPNWatcher struct {
	// config
	IfName         string
	TargetIP       string
	CheckInterval  time.Duration
	PingTimeoutSec int
	NotifyCooldown time.Duration

	// telegram
	TelegramToken   string
	TelegramChatID  string
	TelegramEnabled bool

	// teams
	TeamsWebhookURL string // Microsoft Teams Workflow trigger URL

	// autoreconnect
	AutoReconnect bool
	ReconnectCmd  string
	RecheckDelay  time.Duration

	// state
	mu         sync.RWMutex
	connected  bool
	ifPresent  bool
	ifUp       bool
	viaRoute   bool
	viaPing    bool
	lastChange time.Time
	firstSeen  time.Time
	lastNotif  map[string]time.Time // "up"/"down"
	started    bool
	stopCh     chan struct{}
}

type VPNStatus struct {
	Connected        bool      `json:"connected"`
	Interface        string    `json:"interface"`
	InterfaceUp      bool      `json:"interface_up"`
	InterfacePresent bool      `json:"interface_present"`
	ViaRoute         bool      `json:"via_route"`
	ViaPing          bool      `json:"via_ping"`
	TargetIP         string    `json:"target_ip"`
	LastChange       time.Time `json:"last_change"`
	Since            time.Time `json:"since"`
}

/* =========  CTOR  ========= */

func NewVPNWatcher(ifName, target string, interval time.Duration) *VPNWatcher {
	return &VPNWatcher{
		IfName:          ifName,
		TargetIP:        target,
		CheckInterval:   interval,
		PingTimeoutSec:  2,
		NotifyCooldown:  60 * time.Second,
		RecheckDelay:    5 * time.Second,
		AutoReconnect:   false,
		TelegramEnabled: false,
		lastNotif:       map[string]time.Time{},
		stopCh:          make(chan struct{}),
	}
}

/* =========  CORE LOOP  ========= */

func (w *VPNWatcher) Start() {
	w.mu.Lock()
	if w.started {
		w.mu.Unlock()
		return
	}
	w.firstSeen = time.Now()
	w.lastChange = w.firstSeen
	w.started = true
	w.mu.Unlock()

	// first evaluation immediately
	w.evaluateAndAct()

	t := time.NewTicker(w.CheckInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			w.evaluateAndAct()
		case <-w.stopCh:
			return
		}
	}
}

func (w *VPNWatcher) Stop() { close(w.stopCh) }

func (w *VPNWatcher) Status() VPNStatus {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return VPNStatus{
		Connected:        w.connected,
		Interface:        w.IfName,
		InterfaceUp:      w.ifUp,
		InterfacePresent: w.ifPresent,
		ViaRoute:         w.viaRoute,
		ViaPing:          w.viaPing,
		TargetIP:         w.TargetIP,
		LastChange:       w.lastChange,
		Since:            w.firstSeen,
	}
}

/* =========  EVALUATION + ACTIONS  ========= */

func (w *VPNWatcher) evaluateAndAct() {
	changed, newConnected, ifPresent, ifUp, viaRoute, viaPing := w.evaluateCore()

	if changed {
		state := "DOWN"
		if newConnected {
			state = "UP"
		}
		jsonLog("info", "VPN state changed", map[string]any{
			"state":       state,
			"interface":   w.IfName,
			"target_ip":   w.TargetIP,
			"if_present":  ifPresent,
			"if_up":       ifUp,
			"via_route":   viaRoute,
			"via_ping":    viaPing,
			"last_change": w.lastChange.Format(time.RFC3339Nano),
		})

		// Unified notification (Telegram + Teams)
		if newConnected {
			w.notify("up", "✅ *FortiVPN Connected* — target reachable")
		} else {
			w.notify("down", "❌ *FortiVPN Disconnected* — link or reachability lost")
		}

		// One-shot AutoReconnect: trigger only on transition Connected -> Disconnected
		if w.AutoReconnect && !newConnected {
			go w.tryAutoReconnectOnce()
		}
	}
}

// evaluateCore does the checks and updates state; returns whether state changed and live values
func (w *VPNWatcher) evaluateCore() (changed bool, newConnected, ifPresent, ifUp, viaRoute, viaPing bool) {
	ifPresent, ifUp = checkInterface(w.IfName)
	viaRoute = routeViaInterface(w.TargetIP, w.IfName)
	if ifUp {
		viaPing = pingTargetViaIface(w.TargetIP, w.IfName, w.PingTimeoutSec)
	} else {
		viaPing = false
	}

	newConnected = ifUp && viaRoute && viaPing

	w.mu.Lock()
	prev := w.connected
	w.connected = newConnected
	w.ifPresent = ifPresent
	w.ifUp = ifUp
	w.viaRoute = viaRoute
	w.viaPing = viaPing
	changed = prev != newConnected
	if changed {
		w.lastChange = time.Now()
	}
	w.mu.Unlock()

	return
}

// checkConnectivity performs connectivity check without updating state (read-only)
func (w *VPNWatcher) checkConnectivity() bool {
	ifPresent, ifUp := checkInterface(w.IfName)
	if !ifPresent || !ifUp {
		return false
	}
	viaRoute := routeViaInterface(w.TargetIP, w.IfName)
	if !viaRoute {
		return false
	}
	viaPing := pingTargetViaIface(w.TargetIP, w.IfName, w.PingTimeoutSec)
	return viaPing
}

/* =========  AUTORECONNECT (ONE-SHOT)  ========= */

func (w *VPNWatcher) tryAutoReconnectOnce() {
	if w.ReconnectCmd == "" {
		return
	}
	jsonLog("info", "AutoReconnect triggered", map[string]any{
		"cmd": w.ReconnectCmd,
	})
	// run command
	cmd := exec.Command("bash", "-lc", w.ReconnectCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		jsonLog("error", "AutoReconnect failed to execute", map[string]any{
			"error": err.Error(),
			"out":   string(out),
		})
		return
	}
	jsonLog("info", "AutoReconnect command executed", map[string]any{
		"out": string(out),
	})

	// recheck after delay (read-only check to avoid duplicate state change)
	time.Sleep(w.RecheckDelay)
	connected := w.checkConnectivity()
	jsonLog("info", "AutoReconnect recheck", map[string]any{
		"connected": connected,
	})

	if connected {
		// bypass cooldown and send custom message
		w.notifyWithOptions("up", "✅ *FortiVPN Connected* — auto-reconnect succeeded", true, "auto-reconnect succeeded")
		jsonLog("info", "AutoReconnect success, UP notification sent (bypass cooldown)", nil)

		// Update state manually to reflect the reconnection (prevents duplicate notification on next tick)
		ifPresent, ifUp := checkInterface(w.IfName)
		viaRoute := routeViaInterface(w.TargetIP, w.IfName)
		viaPing := pingTargetViaIface(w.TargetIP, w.IfName, w.PingTimeoutSec)

		w.mu.Lock()
		w.connected = true
		w.ifPresent = ifPresent
		w.ifUp = ifUp
		w.viaRoute = viaRoute
		w.viaPing = viaPing
		w.lastChange = time.Now()
		w.mu.Unlock()
	}
}

/* =========  CHECKERS  ========= */

func checkInterface(name string) (present, up bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, false
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return true, (iface.Flags & net.FlagUp) != 0
		}
	}
	return false, false
}

func routeViaInterface(targetIP, ifName string) bool {
	// `ip route get <targetIP>` → must contain ` dev <ifName>`
	out, err := exec.Command("ip", "route", "get", targetIP).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), " dev "+ifName)
}

func pingTargetViaIface(targetIP, ifName string, timeoutSec int) bool {
	// Debian iputils-ping supports: -c 1, -W <sec>, -I <iface>
	cmd := exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSec), "-I", ifName, targetIP)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

/* =========  NOTIFICATIONS (TELEGRAM + TEAMS)  ========= */

func (w *VPNWatcher) notify(kind, text string) {
	w.notifyWithOptions(kind, text, false, "")
}

// notifyWithOptions handles both Telegram and Teams notifications with optional cooldown bypass and custom message
func (w *VPNWatcher) notifyWithOptions(kind, text string, bypassCooldown bool, customMessage string) {
	connected := kind == "up"

	// Check cooldown (applies to both Telegram and Teams)
	shouldNotify := true
	if !bypassCooldown {
		now := time.Now()
		last := w.lastNotif[kind]
		if now.Sub(last) < w.NotifyCooldown {
			shouldNotify = false
		} else {
			w.lastNotif[kind] = now
		}
	} else {
		w.lastNotif[kind] = time.Now()
	}

	if !shouldNotify {
		return
	}

	// Telegram notification
	if w.TelegramEnabled && w.TelegramToken != "" && w.TelegramChatID != "" {
		if err := sendTelegram(w.TelegramToken, w.TelegramChatID, text, true); err != nil {
			jsonLog("error", "telegram notify error", map[string]any{"error": err.Error()})
		}
	}

	// Teams notification
	if w.TeamsWebhookURL != "" {
		status := "DOWN"
		if connected {
			status = "UP"
		}
		sendTeamsAdaptiveCard(w.TeamsWebhookURL, status, time.Now().Format("2006-01-02 15:04:05"), customMessage)
	}
}

func sendTelegram(token, chatID, text string, markdown bool) error {
	api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	// compact + escape
	text = compactWhitespace(text)
	form := strings.NewReader(fmt.Sprintf(
		"chat_id=%s&text=%s%s",
		urlQueryEscape(chatID),
		urlQueryEscape(text),
		func() string {
			if markdown {
				return "&parse_mode=Markdown"
			}
			return ""
		}(),
	))
	req, _ := http.NewRequest("POST", api, form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New("telegram non-2xx")
	}
	return nil
}

/* =========  TEAMS (ADAPTIVE CARD via Workflow URL)  ========= */

func sendTeamsAdaptiveCard(webhook, status, timestamp, customMessage string) {
	// Build payload matching Power Automate workflow schema
	// The workflow expects: { "status": "UP/DOWN", "time": "timestamp" }
	payload := map[string]string{
		"status": status,
		"time":   timestamp,
	}

	// Add custom message if provided (optional field)
	if customMessage != "" {
		payload["message"] = customMessage
	} else {
		if status == "UP" {
			payload["message"] = "target reachable"
		} else {
			payload["message"] = "link or reachability lost"
		}
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		jsonLog("error", "Teams payload marshal failed", map[string]any{"error": err.Error()})
		return
	}

	req, _ := http.NewRequest("POST", webhook, strings.NewReader(string(payloadJSON)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		jsonLog("error", "Teams notify failed", map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	jsonLog("info", "Teams alert sent", map[string]any{"status": status, "code": resp.StatusCode})
}

/* =========  HTTP  ========= */

func healthHandler(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write([]byte(`{"ok":true}`))
}

func statusHandler(watcher *VPNWatcher) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		st := watcher.Status()
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(st)
	}
}

// Force check: minimal output
func forceCheckHandler(watcher *VPNWatcher) http.HandlerFunc {
	type resp struct {
		Forced    bool `json:"forced"`
		Connected bool `json:"connected"`
	}
	return func(rw http.ResponseWriter, r *http.Request) {
		_, newConnected, _, _, _, _ := watcher.evaluateCore()
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(resp{
			Forced:    true,
			Connected: newConnected,
		})
	}
}

// Prometheus metrics (no labels)
func metricsHandler(watcher *VPNWatcher) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		st := watcher.Status()
		var b strings.Builder
		b.WriteString("# HELP vpn_up Overall VPN connectivity status (1=up, 0=down)\n")
		b.WriteString("# TYPE vpn_up gauge\n")
		b.WriteString(fmt.Sprintf("vpn_up %d\n", boolToInt(st.Connected)))

		b.WriteString("# HELP vpn_interface_up Interface availability (1=up, 0=down)\n")
		b.WriteString("# TYPE vpn_interface_up gauge\n")
		b.WriteString(fmt.Sprintf("vpn_interface_up %d\n", boolToInt(st.InterfaceUp)))

		b.WriteString("# HELP vpn_reachable VPN ping reachability (1=up, 0=down)\n")
		b.WriteString("# TYPE vpn_reachable gauge\n")
		b.WriteString(fmt.Sprintf("vpn_reachable %d\n", boolToInt(st.ViaPing)))

		b.WriteString("# HELP vpn_route_ok Whether the route to target is via VPN interface (1=ok, 0=not)\n")
		b.WriteString("# TYPE vpn_route_ok gauge\n")
		b.WriteString(fmt.Sprintf("vpn_route_ok %d\n", boolToInt(st.ViaRoute)))

		b.WriteString("# HELP vpn_last_change_timestamp Unix timestamp when VPN status last changed\n")
		b.WriteString("# TYPE vpn_last_change_timestamp gauge\n")
		b.WriteString(fmt.Sprintf("vpn_last_change_timestamp %d\n", st.LastChange.Unix()))

		rw.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = rw.Write([]byte(b.String()))
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

/* =========  SERVER BOOT  ========= */

func main() {
	ifName := getenv("FVPN_IFNAME", "ppp0")
	target := getenv("FVPN_TARGET_IP", "10.64.6.42")
	interval := getenvDuration("FVPN_CHECK_INTERVAL", 3*time.Second)
	pingTimeout := getenvInt("FVPN_PING_TIMEOUT", 2)
	notifyCooldown := getenvDuration("FVPN_NOTIFY_COOLDOWN", 60*time.Second)
	recheckDelay := getenvDuration("FVPN_RECHECK_DELAY", 5*time.Second)

	tgToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	tgChatID := os.Getenv("TELEGRAM_CHAT_ID")
	autoReconnect := strings.ToLower(getenv("FVPN_AUTORECONNECT", "false")) == "true"
	reconnectCmd := getenv("FVPN_RECONNECT_CMD", "")
	teamsWebhook := os.Getenv("MS_TEAMS_WEBHOOK_URL")

	w := NewVPNWatcher(ifName, target, interval)
	w.PingTimeoutSec = pingTimeout
	w.NotifyCooldown = notifyCooldown
	w.RecheckDelay = recheckDelay
	w.TelegramToken = tgToken
	w.TelegramChatID = tgChatID
	w.TelegramEnabled = tgToken != "" && tgChatID != ""
	w.AutoReconnect = autoReconnect
	w.ReconnectCmd = reconnectCmd
	w.TeamsWebhookURL = teamsWebhook

	go w.Start()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/vpn/status", statusHandler(w))
	mux.HandleFunc("/vpn/force-check", forceCheckHandler(w))
	mux.HandleFunc("/metrics", metricsHandler(w))

	httpAddr := getenv("HTTP_ADDR", ":8080")
	srv := &http.Server{
		Addr:              httpAddr,
		Handler:           jsonLogMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// startup log
	jsonLog("info", "fortivpn watcher starting", map[string]any{
		"http_addr":       httpAddr,
		"if_name":         ifName,
		"target_ip":       target,
		"check_interval":  interval.String(),
		"ping_timeout_s":  pingTimeout,
		"notify_cooldown": notifyCooldown.String(),
		"autoreconnect":   autoReconnect,
		"reconnect_cmd":   reconnectCmd,
		"recheck_delay":   recheckDelay.String(),
		"teams_webhook":   teamsWebhook != "",
		"telegram":        w.TelegramEnabled,
	})

	// graceful shutdown
	done := make(chan struct{})
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		jsonLog("info", "shutting down", nil)
		_ = srv.Close()
		w.Stop()
		close(done)
	}()

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		jsonLog("fatal", "server error", map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	<-done
}

/* =========  UTILS  ========= */

func jsonLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(rw, r)
		jsonLog("access", "http request", map[string]any{
			"method":  r.Method,
			"path":    r.URL.Path,
			"latency": time.Since(start).String(),
			"remote":  r.RemoteAddr,
		})
	})
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		jsonLog("warn", "invalid duration env, using default", map[string]any{key: v, "default": def.String()})
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
		jsonLog("warn", "invalid int env, using default", map[string]any{key: v, "default": def})
	}
	return def
}

func urlQueryEscape(s string) string {
	// minimal escaping for form body
	replacer := strings.NewReplacer(
		"%", "%25",
		"&", "%26",
		"+", "%2B",
		"=", "%3D",
		"\n", "%0A",
	)
	return replacer.Replace(s)
}
func compactWhitespace(s string) string {
	re := regexp.MustCompile(`[ \t\r\n]+`)
	return re.ReplaceAllString(strings.TrimSpace(s), " ")
}
