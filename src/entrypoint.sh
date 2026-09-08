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
render /opt/udt/templates/dnsmasq.conf.tmpl > /etc/dnsmasq-udt.conf
render /opt/udt/templates/squid.conf.tmpl   > /etc/squid/squid.conf

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
python3 /opt/udt/portal.py & pids+=($!)

echo "[udt] up. portal at http://${UDT_GW}:8080/"
wait -n
echo "[udt] a child process exited; tearing down" >&2
cleanup
