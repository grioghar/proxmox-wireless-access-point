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
    imagemagick python3 openssl curl >/dev/null

# mitmproxy is optional, and since Debian 13 (trixie) it is no longer in the
# archive -- `apt-get install mitmproxy` fails there with "Package 'mitmproxy'
# has no installation candidate". It used to sit on the line above, so under
# `set -e` a trixie host aborted the entire installer having installed nothing
# at all. Keep it separate, fall back to a private venv, and treat total failure
# as non-fatal: entrypoint.sh already degrades to interception-off when the CA
# cannot be made, and everything else works without it.
MITMDUMP_LINK=/usr/local/bin/mitmdump

# `pct exec` runs with PATH=/sbin:/bin:/usr/sbin:/usr/bin -- no /usr/local/bin --
# so `command -v mitmdump` reports "missing" for a perfectly good venv install.
# Test the real locations instead of trusting PATH.
find_mitmdump() {
  for c in /usr/bin/mitmdump /usr/local/bin/mitmdump "$PREFIX/mitmproxy-venv/bin/mitmdump"; do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  command -v mitmdump 2>/dev/null
}

ensure_mitmproxy() {
  [ -n "$(find_mitmdump)" ] && return 0
  if apt-get install -y -qq --no-install-recommends mitmproxy >/dev/null 2>&1 \
     && [ -n "$(find_mitmdump)" ]; then
    return 0
  fi
  echo "==> mitmproxy is not in this release's archive; using a private venv"
  # Keep the output: a silent `|| return 1` here tells you nothing about why,
  # and this step can fail for boring, fixable reasons (no python3-venv, no
  # network, a wheel that will not build).
  local log=/var/log/udt-mitmproxy-install.log
  apt-get install -y -qq --no-install-recommends python3-venv >>"$log" 2>&1 || true
  mkdir -p "$PREFIX"
  python3 -m venv "$PREFIX/mitmproxy-venv" >>"$log" 2>&1 || return 1
  "$PREFIX/mitmproxy-venv/bin/pip" install mitmproxy >>"$log" 2>&1 || return 1
  # mitm.py looks in /usr/bin and /usr/local/bin before falling back to PATH,
  # and entrypoint.sh calls `mitmdump` bare, so the symlink is what wires it up.
  ln -sf "$PREFIX/mitmproxy-venv/bin/mitmdump" "$MITMDUMP_LINK"
  [ -n "$(find_mitmdump)" ]
}
if ensure_mitmproxy; then
  echo "==> mitmproxy: $(find_mitmdump)"
else
  echo "!! mitmproxy unavailable -- TLS interception (UDT_MITM=1) will stay off" >&2
  echo "   details: /var/log/udt-mitmproxy-install.log" >&2
fi

# Debian's packaged units would fight ours for the same interfaces and ports.
# squid in particular auto-starts on install and then refuses ours with
# "Squid is already running".
systemctl disable --now hostapd dnsmasq squid 2>/dev/null || true

echo "==> installing to $PREFIX"
mkdir -p "$PREFIX/templates" /etc/udt /var/lib/udt /var/log/squid /var/run/hostapd
install -m 0755 "$HERE"/src/*.sh "$PREFIX/"
install -m 0755 "$HERE"/src/*.py "$PREFIX/"
install -m 0644 "$HERE"/templates/* "$PREFIX/templates/"
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
