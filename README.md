# FortiVPN Watcher

A lightweight Go application that monitors FortiVPN connectivity and sends real-time notifications via Telegram and Microsoft Teams when the connection status changes.

## Features

- **Real-time VPN Monitoring**: Continuously checks VPN interface status, routing, and target reachability
- **Multi-channel Notifications**: Sends alerts via Telegram (with cooldown) and Microsoft Teams (Adaptive Cards)
- **Auto-reconnect**: Automatically attempts to reconnect when VPN goes down
- **HTTP API**: RESTful endpoints for status checks and health monitoring
- **Prometheus Metrics**: Built-in metrics endpoint for monitoring integration
- **JSON Logging**: Structured logging for easy parsing and analysis
- **Graceful Shutdown**: Handles SIGTERM/SIGINT signals properly

## How It Works

The watcher performs three checks to determine VPN connectivity:

1. **Interface Check**: Verifies the VPN interface exists and is UP
2. **Route Check**: Confirms traffic to target IP routes through the VPN interface
3. **Ping Check**: Tests actual reachability by pinging the target IP via the VPN interface

All three checks must pass for the VPN to be considered "connected".

## Installation

### Prerequisites

- Go 1.25.0 or later
- Linux system with `ip` and `ping` commands
- FortiVPN or similar VPN client configured

### Build from Source

```bash
git clone <repository-url>
cd fortivpn-watcher
go build -o fortivpn-watcher
```

## Configuration

All configuration is done via environment variables:

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `FVPN_IFNAME` | `ppp0` | VPN network interface name |
| `FVPN_TARGET_IP` | `10.64.6.42` | Target IP to check reachability |
| `FVPN_CHECK_INTERVAL` | `3s` | How often to check VPN status |
| `FVPN_PING_TIMEOUT` | `2` | Ping timeout in seconds |
| `FVPN_NOTIFY_COOLDOWN` | `60s` | Minimum time between Telegram notifications |
| `HTTP_ADDR` | `:8080` | HTTP server listen address |

### Auto-reconnect Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `FVPN_AUTORECONNECT` | `false` | Enable automatic reconnection |
| `FVPN_RECONNECT_CMD` | `""` | Shell command to reconnect VPN |
| `FVPN_RECHECK_DELAY` | `5s` | Wait time before rechecking after reconnect |

### Notification Settings

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Optional | Telegram bot token for notifications |
| `TELEGRAM_CHAT_ID` | Optional | Telegram chat ID to send messages |
| `MS_TEAMS_WEBHOOK_URL` | Optional | Microsoft Teams Workflow webhook URL |

## Usage

### Basic Usage

```bash
# Run with defaults
./fortivpn-watcher

# Custom interface and target
export FVPN_IFNAME=tun0
export FVPN_TARGET_IP=192.168.1.1
./fortivpn-watcher
```

### With Telegram Notifications

```bash
export TELEGRAM_BOT_TOKEN=your_bot_token
export TELEGRAM_CHAT_ID=your_chat_id
./fortivpn-watcher
```

### With Auto-reconnect

```bash
export FVPN_AUTORECONNECT=true
export FVPN_RECONNECT_CMD="sudo systemctl restart fortivpn"
./fortivpn-watcher
```

### With Microsoft Teams

```bash
export MS_TEAMS_WEBHOOK_URL="https://your-tenant.webhook.office.com/..."
./fortivpn-watcher
```

### As a systemd Service

Create `/etc/systemd/system/fortivpn-watcher.service`:

```ini
[Unit]
Description=FortiVPN Connection Watcher
After=network.target

[Service]
Type=simple
User=root
Environment="FVPN_IFNAME=ppp0"
Environment="FVPN_TARGET_IP=10.64.6.42"
Environment="TELEGRAM_BOT_TOKEN=your_token"
Environment="TELEGRAM_CHAT_ID=your_chat_id"
Environment="FVPN_AUTORECONNECT=true"
Environment="FVPN_RECONNECT_CMD=systemctl restart fortivpn"
ExecStart=/usr/local/bin/fortivpn-watcher
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable fortivpn-watcher
sudo systemctl start fortivpn-watcher
```

## HTTP API

### Endpoints

#### `GET /healthz`

Health check endpoint.

**Response:**
```json
{"ok": true}
```

#### `GET /vpn/status`

Get current VPN status.

**Response:**
```json
{
  "connected": true,
  "interface": "ppp0",
  "interface_up": true,
  "interface_present": true,
  "via_route": true,
  "via_ping": true,
  "target_ip": "10.64.6.42",
  "last_change": "2024-10-24T06:00:00Z",
  "since": "2024-10-24T05:00:00Z"
}
```

#### `GET /vpn/force-check`

Force an immediate connectivity check.

**Response:**
```json
{
  "forced": true,
  "connected": true
}
```

#### `GET /metrics`

Prometheus-compatible metrics endpoint.

**Response:**
```
vpn_up 1
vpn_interface_up 1
vpn_reachable 1
vpn_route_ok 1
vpn_last_change_timestamp 1729746000
```

## Monitoring with Prometheus

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'fortivpn-watcher'
    static_configs:
      - targets: ['localhost:8080']
```

### Available Metrics

- `vpn_up`: Overall VPN connectivity (1=connected, 0=disconnected)
- `vpn_interface_up`: Interface status (1=up, 0=down)
- `vpn_reachable`: Ping reachability (1=reachable, 0=unreachable)
- `vpn_route_ok`: Route validation (1=correct, 0=incorrect)
- `vpn_last_change_timestamp`: Unix timestamp of last status change

## Notifications

### Telegram

Notifications are sent with a cooldown period (default 60s) to prevent spam:

- ✅ **FortiVPN Connected** — target reachable
- ❌ **FortiVPN Disconnected** — link or reachability lost

Auto-reconnect success notifications bypass the cooldown.

### Microsoft Teams

Adaptive Cards are sent immediately (no cooldown) with color-coded alerts:

- **Green**: VPN Connected
- **Red**: VPN Disconnected

## Logging

All logs are output in JSON format to stdout:

```json
{
  "level": "info",
  "message": "VPN state changed",
  "ts": "2024-10-24T06:00:00.123456789Z",
  "fields": {
    "state": "UP",
    "interface": "ppp0",
    "target_ip": "10.64.6.42"
  }
}
```

## Troubleshooting

### VPN shows as disconnected but it's working

- Check that `FVPN_IFNAME` matches your actual VPN interface name
- Verify `FVPN_TARGET_IP` is reachable through the VPN
- Increase `FVPN_PING_TIMEOUT` if network latency is high

### Auto-reconnect not working

- Ensure the user running the watcher has permission to execute the reconnect command
- Test the `FVPN_RECONNECT_CMD` manually
- Check logs for error messages

### Telegram notifications not received

- Verify `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are correct
- Check that the bot has permission to send messages to the chat
- Look for error messages in the logs

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
