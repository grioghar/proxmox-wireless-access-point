#!/bin/bash
# upside-down-ternet :: first-run wizard
#
# Detects the radio, proves it can actually be an access point, finds a legal
# and uncongested channel, picks a subnet that does not collide with anything
# already on the box, and writes udt.conf.
#
#   ./wizard.sh          interactive setup
#   ./wizard.sh --check  diagnose only, change nothing
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/udt.conf"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

c_r(){ printf '\033[31m%s\033[0m\n' "$*"; }
c_g(){ printf '\033[32m%s\033[0m\n' "$*"; }
c_y(){ printf '\033[33m%s\033[0m\n' "$*"; }
hdr(){ printf '\n\033[1m== %s\033[0m\n' "$*"; }
die(){ c_r "FATAL: $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found. Install: $2"; }

hdr "Prerequisites"
need iw iw
need ip iproute2
c_g "iw and ip present"
[ "$(id -u)" -eq 0 ] || die "run as root (needs to query the radio)"

# ---------------------------------------------------------------- radio ------
hdr "Wireless hardware"
mapfile -t IFACES < <(iw dev 2>/dev/null | awk '/Interface/{print $2}')
[ "${#IFACES[@]}" -gt 0 ] || die "no wireless interface found. Is a card installed and driver loaded?"
for i in "${IFACES[@]}"; do echo "  found: $i"; done

IFACE="${IFACES[0]}"
if [ "${#IFACES[@]}" -gt 1 ] && [ "$CHECK" -eq 0 ]; then
  read -rp "Which interface? [${IFACE}] " a; IFACE="${a:-$IFACE}"
fi
PHY="$(iw dev "$IFACE" info | awk '/wiphy/{print "phy"$2}')"
c_g "using $IFACE ($PHY)"

hdr "AP mode support"
if iw phy "$PHY" info | sed -n '/Supported interface modes/,/^\t[a-zA-Z]/p' | grep -qE '^\s+\* AP$'; then
  c_g "card supports AP mode"
else
  die "this card cannot act as an access point (no 'AP' in supported interface modes).
       Many USB dongles and some Intel cards are station-only. Nothing here can fix that."
fi

# ------------------------------------------------------------ regulatory -----
hdr "Regulatory domain"
SELF_MANAGED=0
iw reg get 2>/dev/null | grep -q 'self-managed' && SELF_MANAGED=1
GLOBAL="$(iw reg get 2>/dev/null | awk '/^country/{print $2; exit}')"
PHYREG="$(iw phy "$PHY" reg get 2>/dev/null | awk '/^country/{print $2; exit}')"
echo "  global domain: ${GLOBAL:-unknown}"
[ -n "$PHYREG" ] && echo "  card domain:   $PHYREG"

if [ ! -e /lib/firmware/regulatory.db ]; then
  c_y "  wireless-regdb is NOT installed -- the kernel will ignore every regulatory"
  c_y "  hint and fall back to the world domain, which forbids 5 GHz AP mode."
  c_y "  Fix on the HOST (not in the container): apt install wireless-regdb"
fi
if [ "$SELF_MANAGED" -eq 1 ]; then
  c_y "  This card is SELF-MANAGED (Intel LAR and similar). 'iw reg set' changes the"
  c_y "  global domain but NOT the card's own, and the card's is what governs."
  c_y "  If its domain reads 00, 5 GHz AP mode will be refused no matter what you set."
fi

# --------------------------------------------------------------- channel ----
hdr "Usable channels"
usable() { # $1 = 2 or 5
  local re='^\s+\* 2[0-9]{3}' ; [ "$1" = 5 ] && re='^\s+\* 5[0-9]{3}'
  iw phy "$PHY" info | grep -E "$re" | grep -v 'no IR' | grep -v 'disabled' \
    | grep -oE '\[[0-9]+\]' | tr -d '[]'
}
mapfile -t CH24 < <(usable 2)
mapfile -t CH5  < <(usable 5)
echo "  2.4 GHz: ${CH24[*]:-none}"
echo "  5 GHz:   ${CH5[*]:-none}"
[ "${#CH24[@]}" -eq 0 ] && [ "${#CH5[@]}" -eq 0 ] && \
  die "no channel permits AP transmission. This is almost always the regulatory
       problem described above, not a broken card."

hdr "Channel congestion"
BEST24=6; BEST5=""
if ip link set "$IFACE" up 2>/dev/null && iw dev "$IFACE" scan >/tmp/udt-scan 2>/dev/null; then
  echo "  neighbours per channel:"
  grep -oE 'primary channel: [0-9]+' /tmp/udt-scan | awk '{print $3}' \
    | sort -n | uniq -c | sort -rn | head -8 | sed 's/^/    /'
  for c in 1 6 11; do
    n=$(grep -c "primary channel: $c\$" /tmp/udt-scan 2>/dev/null || echo 0)
    echo "    ch $c: $n neighbours"
  done
  BEST24=$(for c in 1 6 11; do
             printf '%s %s\n' "$(grep -c "primary channel: $c\$" /tmp/udt-scan 2>/dev/null||echo 0)" "$c"
           done | sort -n | head -1 | awk '{print $2}')
  for c in "${CH5[@]}"; do
    n=$(grep -c "primary channel: $c\$" /tmp/udt-scan 2>/dev/null || echo 0)
    [ -z "$BEST5" ] && BEST5="$c"
    [ "$n" = "0" ] && { BEST5="$c"; break; }
  done
  rm -f /tmp/udt-scan
else
  c_y "  scan failed (interface busy?); defaulting to 2.4 GHz ch 6"
fi

if [ "${#CH5[@]}" -gt 0 ] && [ -n "$BEST5" ]; then
  HW=a; CHAN="$BEST5"; c_g "recommending 5 GHz channel $CHAN"
else
  HW=g; CHAN="${BEST24:-6}"; c_g "recommending 2.4 GHz channel $CHAN"
fi

# --------------------------------------------------------------- uplink -----
hdr "Uplink and addressing"
UPLINK="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
[ -n "$UPLINK" ] || die "no default route -- cannot determine the internet-facing interface"
c_g "uplink: $UPLINK"

pick_subnet() {
  for third in 83 84 85 86 87 90 91 92; do
    if ! ip -4 route 2>/dev/null | grep -q "10\.$third\."; then echo "$third"; return; fi
  done
  echo 83
}
THIRD="$(pick_subnet)"
NET="10.$THIRD.0.0/24"; GW="10.$THIRD.0.1"
c_g "portal subnet: $NET (gateway $GW)"

if [ "$CHECK" -eq 1 ]; then
  hdr "Check complete"
  echo "No files were written. Re-run without --check to configure."
  exit 0
fi

# ---------------------------------------------------------------- prompt ----
hdr "Configuration"
read -rp "SSID [upside-down-ternet]: " SSID; SSID="${SSID:-upside-down-ternet}"
read -rp "Channel [$CHAN]: " a; CHAN="${a:-$CHAN}"
read -rsp "WPA2 passphrase (blank = open network, portal is the gate): " PSK; echo
[ -n "$PSK" ] && [ "${#PSK}" -lt 8 ] && die "a WPA2 passphrase must be at least 8 characters"
read -rp "Guest bandwidth cap [128kbit]: " RG; RG="${RG:-128kbit}"
read -rp "Standard tier cap [5mbit]: " RS; RS="${RS:-5mbit}"
read -rp "Trusted tier cap [100mbit]: " RT; RT="${RT:-100mbit}"
read -rp "Retain consent records for how many days? [30]: " RET; RET="${RET:-30}"
read -rp "Flip images on cleartext HTTP? [Y/n]: " FL
FLIP=1; case "${FL:-y}" in [Nn]*) FLIP=0 ;; esac

cat > "$OUT" <<CONF
# Generated by wizard.sh on $(date -Iseconds)
UDT_IFACE=$IFACE
UDT_SSID=$SSID
UDT_CHANNEL=$CHAN
UDT_HW_MODE=$HW
UDT_COUNTRY=${GLOBAL:-US}
UDT_PASSPHRASE=$PSK

UDT_NET=$NET
UDT_GW=$GW
UDT_DHCP_START=10.$THIRD.0.50
UDT_DHCP_END=10.$THIRD.0.200
UDT_UPLINK=$UPLINK

UDT_RATE=$RG
UDT_RATE_STANDARD=$RS
UDT_RATE_TRUSTED=$RT

UDT_FLIP=$FLIP
UDT_RETENTION_DAYS=$RET
UDT_DNS1=1.1.1.1
UDT_DNS2=8.8.8.8
CONF
chmod 600 "$OUT"

hdr "Done"
c_g "wrote $OUT"
echo
echo "Next:"
echo "  docker compose up -d --build"
echo "  docker compose logs -f"
echo
echo "Then connect a phone to '$SSID' and the portal should appear."
echo "Operator commands:  docker exec -it upside-down-ternet python3 /opt/udt/udtctl.py who"
