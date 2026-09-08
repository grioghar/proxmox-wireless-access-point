#!/bin/bash
# upside-down-ternet :: native installer (no Docker)
#
# Works on any Debian-family host that owns the radio:
#   * directly on a Proxmox node
#   * inside a privileged LXC that has had a wireless phy handed to it
#     (see lxc/create-udt-lxc.sh)
#
# Installs to /opt/udt and registers a systemd service.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX=/opt/udt

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

echo "==> installing dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    hostapd dnsmasq squid-openssl iptables iproute2 iw wireless-regdb \
    imagemagick python3 openssl curl mitmproxy >/dev/null

# Debian's packaged units would fight ours for the same interfaces and ports.
# squid in particular auto-starts on install and then refuses ours with
# "Squid is already running".
systemctl disable --now hostapd dnsmasq squid 2>/dev/null || true

echo "==> installing to $PREFIX"
mkdir -p "$PREFIX/templates" /etc/udt /var/lib/udt /var/log/squid /var/run/hostapd
install -m 0755 "$HERE"/src/*.sh "$PREFIX/"
install -m 0755 "$HERE"/src/*.py "$PREFIX/"
install -m 0644 "$HERE"/templates/*.tmpl "$PREFIX/templates/"
ln -sf "$PREFIX/udtctl.py" /usr/local/bin/udtctl

if [ ! -f /etc/squid/dummy.pem ]; then
  echo "==> generating squid port certificate (never shown to clients; splice mode)"
  mkdir -p /etc/squid
  openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem -days 3650 \
      -nodes -subj "/CN=upside-down-ternet" 2>/dev/null
  cat /tmp/k.pem /tmp/c.pem > /etc/squid/dummy.pem
  rm -f /tmp/k.pem /tmp/c.pem
  chown proxy:proxy /etc/squid/dummy.pem 2>/dev/null || true
  chmod 400 /etc/squid/dummy.pem
fi

if [ ! -f /etc/udt/udt.conf ]; then
  if [ -f "$HERE/udt.conf" ]; then
    install -m 0600 "$HERE/udt.conf" /etc/udt/udt.conf
    echo "==> installed udt.conf from $HERE"
  else
    echo
    echo "No configuration yet. Run the wizard, then re-run this installer:"
    echo "    $HERE/wizard.sh"
    exit 0
  fi
fi

cat > /etc/systemd/system/upside-down-ternet.service <<'UNIT'
[Unit]
Description=upside-down-ternet captive portal AP
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=UDT_CONF=/etc/udt/udt.conf
ExecStart=/opt/udt/entrypoint.sh
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
echo
echo "==> installed. Start it with:"
echo "    systemctl enable --now upside-down-ternet"
echo "    journalctl -u upside-down-ternet -f"
echo
echo "Operator commands:  udtctl who | udtctl trust <mac|email> | udtctl export"
