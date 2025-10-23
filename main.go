package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
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

type VPNWatcher struct {
	// config
	IfName         string        // ppp0
	TargetIP       string        // 10.64.6.42
	CheckInterval  time.Duration // e.g. 3s
	PingTimeoutSec int           // e.g. 2
	NotifyCooldown time.Duration // e.g. 60s

	// telegram
	TelegramToken   string
	TelegramChatID  string
	TelegramEnabled bool

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

func NewVPNWatcher(ifName, target string, interval time.Duration) *VPNWatcher {
	return &VPNWatcher{
		IfName:          ifName,
		TargetIP:        target,
		CheckInterval:   interval,
		PingTimeoutSec:  2,
		NotifyCooldown:  60 * time.Second,
		TelegramEnabled: false,
		lastNotif:       map[string]time.Time{},
		stopCh:          make(chan struct{}),
	}
}

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

	// do first evaluation immediately
	w.evaluateAndMaybeNotify()

	t := time.NewTicker(w.CheckInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			w.evaluateAndMaybeNotify()
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

func (w *VPNWatcher) evaluateAndMaybeNotify() {
	ifPresent, ifUp := checkInterface(w.IfName)
	viaRoute := routeViaInterface(w.TargetIP, w.IfName)
	viaPing := false
	if ifUp {
		viaPing = pingTargetViaIface(w.TargetIP, w.IfName, w.PingTimeoutSec)
	}

	newConnected := ifUp && viaRoute && viaPing

	w.mu.Lock()
	prev := w.connected
	w.connected = newConnected
	w.ifPresent = ifPresent
	w.ifUp = ifUp
	w.viaRoute = viaRoute
	w.viaPing = viaPing

	statusChanged := prev != newConnected
	if statusChanged {
		w.lastChange = time.Now()
	}
	w.mu.Unlock()

	if statusChanged {
		if newConnected {
			w.notify("up", "✅ *FortiVPN Connected* — target reachable")
		} else {
			w.notify("down", "❌ *FortiVPN Disconnected* — link or reachability lost")
		}
	}
}

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
	// `ip route get <targetIP>` → look for "dev ppp0"
	out, err := exec.Command("ip", "route", "get", targetIP).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), " dev "+ifName)
}

func pingTargetViaIface(targetIP, ifName string, timeoutSec int) bool {
	// Use external ping: Debian iputils-ping supports -c, -W (sec), -I <iface>
	cmd := exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", timeoutSec), "-I", ifName, targetIP)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func (w *VPNWatcher) notify(kind, text string) {
	if !w.TelegramEnabled || w.TelegramToken == "" || w.TelegramChatID == "" {
		return
	}
	now := time.Now()
	last := w.lastNotif[kind]
	if now.Sub(last) < w.NotifyCooldown {
		return
	}
	w.lastNotif[kind] = now
	if err := sendTelegram(w.TelegramToken, w.TelegramChatID, text, true); err != nil {
		log.Printf("[vpn] telegram error: %v", err)
	}
}

func sendTelegram(token, chatID, text string, markdown bool) error {
	api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	// prevent excessive whitespace/linebreaks
	text = compactWhitespace(text)

	form := strings.NewReader(fmt.Sprintf("chat_id=%s&text=%s&parse_mode=%s",
		urlQueryEscape(chatID), urlQueryEscape(text), ternary(markdown, "Markdown", "")))
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

// --- helpers for telegram form ---
func urlQueryEscape(s string) string {
	// minimal escape (no external libs)
	replacer := strings.NewReplacer(
		"%", "%25",
		"&", "%26",
		"+", "%2B",
		"=", "%3D",
		"\n", "%0A",
	)
	return replacer.Replace(s)
}
func ternary[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
func compactWhitespace(s string) string {
	re := regexp.MustCompile(`[ \t\r\n]+`)
	return re.ReplaceAllString(strings.TrimSpace(s), " ")
}

// --- HTTP ---

func statusHandler(watcher *VPNWatcher) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		st := watcher.Status()
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(st)
	}
}
func healthHandler(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	_, _ = rw.Write([]byte(`{"ok":true}`))
}

// --- main ---

func main() {
	ifName := getenv("FVPN_IFNAME", "ppp0")
	target := getenv("FVPN_TARGET_IP", "10.64.6.42")
	interval := getenvDuration("FVPN_CHECK_INTERVAL", 3*time.Second)
	pingTimeout := getenvInt("FVPN_PING_TIMEOUT", 2)
	notifyCooldown := getenvDuration("FVPN_NOTIFY_COOLDOWN", 60*time.Second)

	tgToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	tgChatID := os.Getenv("TELEGRAM_CHAT_ID")

	w := NewVPNWatcher(ifName, target, interval)
	w.PingTimeoutSec = pingTimeout
	w.NotifyCooldown = notifyCooldown
	w.TelegramToken = tgToken
	w.TelegramChatID = tgChatID
	w.TelegramEnabled = tgToken != "" && tgChatID != ""

	// start watcher
	go w.Start()

	// HTTP
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/vpn/status", statusHandler(w))

	httpAddr := getenv("HTTP_ADDR", ":8080")
	srv := &http.Server{Addr: httpAddr, Handler: logMiddleware(mux), ReadHeaderTimeout: 5 * time.Second}

	// graceful shutdown
	done := make(chan struct{})
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Println("shutting down...")
		_ = srv.Close()
		w.Stop()
		close(done)
	}()

	log.Printf("fortivpn watcher on %s (if=%s, target=%s)", httpAddr, ifName, target)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
	<-done
}

// --- utilities ---

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(rw, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
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
		log.Printf("invalid duration %s=%q, using %s", key, v, def)
	}
	return def
}
func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
		log.Printf("invalid int %s=%q, using %d", key, v, def)
	}
	return def
}
