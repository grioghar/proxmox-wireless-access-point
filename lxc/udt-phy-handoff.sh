#!/bin/bash
# Move a wireless PHY into an LXC's network namespace.
#
#   udt-phy-handoff.sh <CTID> [PHY]
#
# A wireless device belongs to exactly one network namespace at a time. Moving
# the PHY (not the interface) is the supported operation -- it carries all of the
# device's interfaces with it. While the container holds it, the host cannot use
# that radio; it returns when the container's netns is destroyed.
set -eu

CTID="${1:?usage: udt-phy-handoff.sh <CTID> [PHY]}"
PHY="${2:-}"

die() { echo "FATAL: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root on the Proxmox host"

if [ -z "$PHY" ]; then
  PHY="$(ls /sys/class/ieee80211/ 2>/dev/null | head -1)"
fi
[ -n "$PHY" ] || die "no wireless phy specified or found"
[ -d "/sys/class/ieee80211/$PHY" ] || {
  # Already inside the container? Then there is nothing to do.
  if pct exec "$CTID" -- test -d "/sys/class/ieee80211/$PHY" 2>/dev/null; then
    echo "$PHY is already inside CT $CTID"; exit 0
  fi
  die "$PHY not present on the host"
}

PID="$(lxc-info -n "$CTID" -p -H 2>/dev/null | tr -d ' ')"
[ -n "$PID" ] && [ "$PID" != "-1" ] || die "CT $CTID is not running"

# Free the radio from anything holding it on the host.
systemctl stop hostapd wpa_supplicant 2>/dev/null || true
for i in $(iw dev 2>/dev/null | awk -v p="$PHY" '$1=="phy#"substr(p,4){f=1} /Interface/{if(f)print $2}'); do
  ip link set "$i" down 2>/dev/null || true
done

echo "moving $PHY into CT $CTID (netns pid $PID)"
iw phy "$PHY" set netns "$PID" || die "failed to move $PHY into the container namespace"

sleep 1
if pct exec "$CTID" -- test -d "/sys/class/ieee80211/$PHY" 2>/dev/null; then
  echo "OK: CT $CTID now owns $PHY"
  pct exec "$CTID" -- iw dev 2>/dev/null | sed 's/^/  /' || true
else
  die "move reported success but $PHY is not visible inside the container"
fi
