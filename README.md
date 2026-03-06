# Arx-UI

An advanced multi-protocol VPN management panel with web UI. Supports **Xray** (VMess, VLESS, Trojan, Shadowsocks, etc.), **L2TP/IPsec**, **PPTP**, and **OpenVPN** — all managed from a single panel with per-client traffic tracking.

## Features

- **Multi-protocol**: VMess, VLESS, Trojan, Shadowsocks, L2TP/IPsec, PPTP, OpenVPN
- **Web panel**: Clean UI for managing inbounds, clients, and settings
- **Per-client tracking**: Traffic limits, expiry dates, IP limits, real-time stats
- **Telegram bot**: Notifications, client management, and server monitoring
- **Subscription server**: Auto-generate client configs
- **Multi-language**: English, Farsi, Chinese, Russian, Turkish, Arabic, and more
- **SSL support**: Optional Let's Encrypt (domain or IP) or custom certificate

## Installation

### Quick Install (Recommended)

Run as root on a fresh Linux server (Debian 12+, Ubuntu 22.04+, CentOS 8+, Fedora, Arch, Alpine):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Arman2122/Arx-ui/main/install.sh)
```

The installer will:
1. Install required dependencies
2. Download the latest Arx-UI release
3. Generate random admin credentials (username, password, port, webBasePath)
4. Optionally set up SSL (you can skip this)
5. Start the panel and display your access URL

### Install a Specific Version

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Arman2122/Arx-ui/main/install.sh) v2.8.10
```

### After Installation

Save the credentials displayed at the end of the install. Access the panel at:

```
http://YOUR_SERVER_IP:PORT/WEBBASEPATH
```

For example: `http://123.45.67.89:54321/abc123def456`

### Management Commands

After installation, use the `arx-ui` command:

```bash
arx-ui              # Open management menu
arx-ui start        # Start panel
arx-ui stop         # Stop panel
arx-ui restart      # Restart panel
arx-ui status       # Check status
arx-ui settings     # Show current settings
arx-ui enable       # Enable autostart
arx-ui disable      # Disable autostart
arx-ui log          # View logs
arx-ui update       # Update to latest version
arx-ui uninstall    # Uninstall
```

## VPN Backend Setup (L2TP/PPTP/OpenVPN)

If you want to use L2TP/IPsec, PPTP, or OpenVPN protocols, run the VPN backend setup after installing the panel:

```bash
sudo ./setup-vpn-backend.sh install     # First-time setup
sudo ./setup-vpn-backend.sh update      # Re-apply config on existing install
sudo ./setup-vpn-backend.sh uninstall   # Remove VPN backend
```

This installs and configures `xl2tpd`, `libreswan`, `pptpd`, `openvpn`, `ppp`, and `nftables`.

## Build from Source

```bash
# Install Go 1.21+ and build tools
apt-get install -y golang gcc libc6-dev git

# Clone and build
git clone https://github.com/Arman2122/Arx-ui.git
cd Arx-ui
CGO_ENABLED=1 go build -o arx-ui main.go

# Install Xray
mkdir -p /usr/local/arx-ui/bin
XRAY_VERSION="25.1.1"
curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" -o /tmp/xray.zip
unzip -o /tmp/xray.zip -d /tmp/xray
cp /tmp/xray/xray /usr/local/arx-ui/bin/xray-linux-amd64
chmod +x /usr/local/arx-ui/bin/xray-linux-amd64
cp /tmp/xray/geo*.dat /usr/local/arx-ui/bin/ 2>/dev/null || true
rm -rf /tmp/xray /tmp/xray.zip

# Deploy
cp arx-ui /usr/local/arx-ui/
cd /usr/local/arx-ui
./arx-ui run
```

### Run as systemd service

```bash
cat > /etc/systemd/system/arx-ui.service << 'EOF'
[Unit]
Description=Arx-UI Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/arx-ui/arx-ui run
WorkingDirectory=/usr/local/arx-ui
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now arx-ui
```

## Docker

```bash
# Using docker compose
docker compose up -d

# Or manually
docker run -d \
  --name arx-ui \
  --restart unless-stopped \
  -p 2053:2053 \
  -p 443:443 \
  -v ./db/:/etc/arx-ui/ \
  -v ./cert/:/root/cert/ \
  ghcr.io/arman2122/arx-ui:latest
```

## SSL Certificate (Optional)

SSL is optional during install. You can set it up later from the management menu:

```bash
arx-ui
# Choose option 16 (SSL Certificate Management)
```

Or directly via `install.sh` which offers:
1. **Let's Encrypt for Domain** — 90-day auto-renewing certificate (needs port 80 open)
2. **Let's Encrypt for IP** — 6-day auto-renewing certificate (needs port 80 open)
3. **Custom certificate** — Use your own cert/key files
4. **Skip** — Run on HTTP only

## Usage Guide

### Creating Inbounds (Xray Protocols)

1. Open the panel in your browser
2. Click **Add Inbound**
3. Select a protocol (VMess, VLESS, Trojan, Shadowsocks, etc.)
4. Configure port, security settings, transport
5. Click **Add** to save
6. Add clients via the **+** button on the inbound row

### Creating L2TP/IPsec Inbound

1. Click **Add Inbound** > Select **l2tp**
2. Configure:
   - **Port**: `1701`
   - **IP Range**: `10.0.2.10-10.0.2.50`
   - **Local IP**: `10.0.2.1`
   - **DNS**: `8.8.8.8`, `1.1.1.1`
   - **IPsec**: Enable + set a Pre-Shared Key
3. Add clients with Username/Password

**Client connection settings:**
- Server: Your server IP
- Type: L2TP/IPsec PSK
- PSK: As configured
- Username/Password: As configured

### Creating PPTP Inbound

1. Click **Add Inbound** > Select **pptp**
2. Configure port `1723`, IP range, local IP, DNS
3. Add clients with Username/Password

### Creating OpenVPN Inbound

1. Click **Add Inbound** > Select **openvpn**
2. Configure UDP port (`1194`), TCP port (`443`), DNS
3. Click **Generate Self-Signed CA** to create certificates
4. Add clients, then download `.ovpn` config files (UDP or TCP)

### Telegram Bot

1. Create a bot via [@BotFather](https://t.me/BotFather)
2. Go to Panel Settings > Telegram
3. Enter your bot token and admin chat ID
4. Enable notifications for traffic, expiry, login alerts

## Supported OS

| OS | Supported Versions |
|----|--------------------|
| Ubuntu | 20.04+ |
| Debian | 10+ |
| CentOS | 8+ |
| Fedora | 36+ |
| Arch Linux | Rolling |
| Alpine | 3.15+ |
| Amazon Linux | 2+ |

Supported architectures: `amd64`, `arm64`, `armv7`, `armv6`, `armv5`, `s390x`

## Notes

- Default panel port: `2053`
- The panel auto-generates VPN configs at runtime — no manual config editing needed
- For Windows L2TP behind NAT: set registry key `AssumeUDPEncapsulationContextOnSendRule` (DWORD `2`) at `HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent`
- Cloud/minimal kernels may lack PPP modules — install `linux-image-amd64` and reboot if needed

## License

GPL-3.0
