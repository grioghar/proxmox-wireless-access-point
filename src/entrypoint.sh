#!/bin/bash
# upside-down-ternet :: container entrypoint
set -u
CONF=/etc/udt/udt.conf
[ -f "$CONF" ] || { echo "FATAL: /etc/udt/udt.conf not mounted. Run ./wizard.sh first." >&2; exit 1; }
. "$CONF"
export UDT_CONF="$CONF"

render() {
  sed -e "s|__IFACE__|${UDT_IFACE}|g"      -e "s|__SSID__|${UDT_SSID}|g" \
      -e "s|__HW_MODE__|${UDT_HW_MODE}|g"  -e "s|__CHANNEL__|${UDT_CHANNEL}|g" \
      -e "s|__GW__|${UDT_GW}|g"            -e "s|__NET__|${UDT_NET}|g" \
      -e "s|__DHCP_START__|${UDT_DHCP_START}|g" -e "s|__DHCP_END__|${UDT_DHCP_END}|g" \
      -e "s|__DNS1__|${UDT_DNS1}|g"        -e "s|__DNS2__|${UDT_DNS2}|g" \
      -e "s|__FLIP_PORT__|3129|g" "$1"
}

render /opt/udt/templates/hostapd.conf.tmpl > /etc/hostapd.conf
if [ -n "${UDT_PASSPHRASE:-}" ]; then
  { echo "wpa=2"; echo "wpa_key_mgmt=WPA-PSK"; echo "rsn_pairwise=CCMP"
    echo "wpa_passphrase=${UDT_PASSPHRASE}"; } >> /etc/hostapd.conf
fi
# ---- lab mode: WPA2 + MAC allowlist ---------------------------------------
if [ "${UDT_MODE:-public}" = "lab" ]; then
  if [ -z "${UDT_PASSPHRASE:-}" ]; then
    echo "FATAL: UDT_MODE=lab requires UDT_PASSPHRASE. A private lab should not" >&2
    echo "       be an open network. Set one in udt.conf." >&2
    exit 1
  fi
  touch /etc/udt/allowed_macs
  n_allowed=$(grep -cvE '^\s*(#|$)' /etc/udt/allowed_macs || true)
  if [ "${n_allowed:-0}" -gt 0 ]; then
    { echo "macaddr_acl=1"; echo "accept_mac_file=/etc/udt/allowed_macs"; } >> /etc/hostapd.conf
    echo "[udt] lab mode: WPA2 + MAC allowlist ($n_allowed device(s) permitted)"
  else
    # Enforcing an empty allowlist would lock you out with no way to discover
    # your own MAC. WPA2 alone is the gate until you add the first device.
    echo "[udt] lab mode: WPA2 only -- allowlist is empty, so it is not enforced."
    echo "[udt]   add devices with 'udtctl allow <mac>' to lock this down further."
  fi
fi

render /opt/udt/templates/dnsmasq.conf.tmpl > /etc/dnsmasq-udt.conf
render /opt/udt/templates/squid.conf.tmpl   > /etc/squid/squid.conf

# The cert-check hostname must resolve to us, and only for our own clients.
if [ "${UDT_MITM:-0}" = "1" ]; then
  echo "address=/${UDT_MITM_CHECK_HOST:-mitm-check.udt}/${UDT_GW}" >> /etc/dnsmasq-udt.conf
fi

# The AX200-class regulatory trap: many cards report country 00 until told
# otherwise, which silently forbids 5 GHz AP mode. Set it before hostapd starts.
iw reg set "${UDT_COUNTRY:-US}" 2>/dev/null || true

echo "[udt] preparing ${UDT_IFACE} ..."
ip link set "$UDT_IFACE" down 2>/dev/null
iw dev "$UDT_IFACE" set type managed 2>/dev/null
ip link set "$UDT_IFACE" up 2>/dev/null

pids=()
cleanup() { echo "[udt] shutting down"; /opt/udt/udt-net.sh down; kill "${pids[@]}" 2>/dev/null; exit 0; }
trap cleanup TERM INT

echo "[udt] starting hostapd (SSID '${UDT_SSID}', ch ${UDT_CHANNEL})"
hostapd /etc/hostapd.conf & pids+=($!)
sleep 5
if ! kill -0 "${pids[0]}" 2>/dev/null; then
  echo "FATAL: hostapd exited. Common causes: the channel is not permitted for AP" >&2
  echo "       mode in this regulatory domain, or the card lacks AP support." >&2
  echo "       Run ./wizard.sh --check for a diagnosis." >&2
  exit 1
fi

echo "[udt] applying firewall + shaping"
/opt/udt/udt-net.sh up

echo "[udt] starting dnsmasq / flipproxy / squid / portal"
dnsmasq -k -C /etc/dnsmasq-udt.conf & pids+=($!)
[ "${UDT_FLIP:-1}" = "1" ] && { python3 /opt/udt/flipproxy.py & pids+=($!); }
# A distro squid may already be running (Debian starts it on install) or may
# have left a stale pid file; either makes ours abort with "already running".
systemctl stop squid 2>/dev/null || true
pkill -x squid 2>/dev/null || true
rm -f /var/run/squid.pid
sleep 1
squid -N -f /etc/squid/squid.conf & pids+=($!)

# ---- optional TLS interception --------------------------------------------
# Started only when explicitly enabled. Even then it receives traffic solely
# from devices carrying the 0x04 mark, which requires a proven CA handshake.
if [ "${UDT_MITM:-0}" = "1" ]; then
  export UDT_MITM_CONFDIR=/var/lib/udt/mitm
  export UDT_MITM_CHECK_HOST UDT_MITM_CHECK_PORT
  echo "[udt] preparing mitmproxy CA"
  if python3 /opt/udt/mitm.py ensure-ca; then
    mitmdump --mode transparent --showhost -q \
             --set confdir=/var/lib/udt/mitm \
             --listen-port "${UDT_MITM_PORT:-8081}" \
             -s /opt/udt/mitm_addon.py \
             -w /var/lib/udt/mitm-flows & pids+=($!)
    python3 /opt/udt/mitm.py check-server & pids+=($!)
    echo "[udt] TLS interception ARMED (opt-in, cert-gated). CA: http://${UDT_GW}:8080/ca.crt"
  else
    echo "[udt] WARNING: mitmproxy CA unavailable; interception stays off" >&2
  fi
fi

python3 /opt/udt/portal.py & pids+=($!)

if [ "${UDT_MONITOR:-1}" = "1" ]; then
  python3 /opt/udt/monitor.py & pids+=($!)
fi

# Optionally shrink the radio so the cell does not spill past the building.
if [ -n "${UDT_TXPOWER:-}" ]; then
  iw dev "$UDT_IFACE" set txpower fixed "$UDT_TXPOWER" 2>/dev/null \
    && echo "[udt] txpower fixed at ${UDT_TXPOWER} mBm"
fi

echo "[udt] up. portal at http://${UDT_GW}:8080/"
wait -n
echo "[udt] a child process exited; tearing down" >&2
cleanup
