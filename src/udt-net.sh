#!/bin/bash
# upside-down-ternet :: network enforcement layer
#
# Model: every client starts UNAUTHORIZED. Unauthorized clients can reach only
# DNS and the captive portal. Once they consent, their MAC is marked and they
# gain HTTP/HTTPS only -- everything else stays dropped, which is what kills
# BitTorrent, WireGuard and friends.
#
# Bandwidth is tiered per client IP: guest (default), standard, trusted.
set -u
CONF="${UDT_CONF:-/etc/udt/udt.conf}"
[ -f "$CONF" ] && . "$CONF"

IF="${UDT_IFACE:-wlan0}"
NET="${UDT_NET:-10.83.0.0/24}"
GW="${UDT_GW:-10.83.0.1}"
UPLINK="${UDT_UPLINK:-vmbr0}"
PORTAL_PORT=8080
SQUID_HTTP=3128
SQUID_HTTPS=3130
MARK=0x83

TIERS_FILE="${UDT_TIERS:-/var/lib/udt/tiers}"
R_GUEST="${UDT_RATE:-128kbit}"
R_STANDARD="${UDT_RATE_STANDARD:-5mbit}"
R_TRUSTED="${UDT_RATE_TRUSTED:-100mbit}"

ipt() { iptables "$@"; }

flush_chains() {
  ipt -t mangle -D PREROUTING -i "$IF" -j UDT_MARK 2>/dev/null
  ipt -t mangle -F UDT_MARK 2>/dev/null; ipt -t mangle -X UDT_MARK 2>/dev/null
  ipt -t nat -D PREROUTING -i "$IF" -j UDT_NAT 2>/dev/null
  ipt -t nat -F UDT_NAT 2>/dev/null; ipt -t nat -X UDT_NAT 2>/dev/null
  ipt -D FORWARD -j UDT_FWD 2>/dev/null
  ipt -F UDT_FWD 2>/dev/null; ipt -X UDT_FWD 2>/dev/null
  ipt -t nat -D POSTROUTING -s "$NET" -o "$UPLINK" -j MASQUERADE 2>/dev/null
}

up() {
  flush_chains
  ip addr flush dev "$IF" 2>/dev/null
  ip addr add "$GW/24" dev "$IF" 2>/dev/null
  ip link set "$IF" up
  sysctl -qw net.ipv4.ip_forward=1

  # ---- MARK: authorized MACs get $MARK stamped on their packets -------------
  ipt -t mangle -N UDT_MARK
  ipt -t mangle -A PREROUTING -i "$IF" -j UDT_MARK

  # ---- NAT: portal capture + transparent proxy ------------------------------
  ipt -t nat -N UDT_NAT
  ipt -t nat -A PREROUTING -i "$IF" -j UDT_NAT
  # authorized -> squid (logs; squid hands HTTP to the flip proxy as parent)
  ipt -t nat -A UDT_NAT -p tcp --dport 80  -m mark --mark $MARK -j REDIRECT --to-ports $SQUID_HTTP
  ipt -t nat -A UDT_NAT -p tcp --dport 443 -m mark --mark $MARK -j REDIRECT --to-ports $SQUID_HTTPS
  # unauthorized -> captive portal (HTTP only; 443 is dropped so OS probes fire)
  ipt -t nat -A UDT_NAT -p tcp --dport 80 -j REDIRECT --to-ports $PORTAL_PORT
  ipt -t nat -A POSTROUTING -s "$NET" -o "$UPLINK" -j MASQUERADE

  # ---- FORWARD: default deny ------------------------------------------------
  ipt -N UDT_FWD
  ipt -I FORWARD -j UDT_FWD
  # client isolation at L3 (hostapd ap_isolate handles L2)
  ipt -A UDT_FWD -i "$IF" -o "$IF" -j DROP
  # never let the portal network touch RFC1918 space
  for p in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    ipt -A UDT_FWD -i "$IF" -d "$p" -j REJECT --reject-with icmp-admin-prohibited
  done
  # return traffic
  ipt -A UDT_FWD -o "$IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  # explicit VPN / tunnel denials (logged, so you can see who tried)
  ipt -A UDT_FWD -i "$IF" -p udp -m multiport --dports 51820,500,4500,1194,1701,1723 \
      -j LOG --log-prefix "UDT-VPN-BLOCK " --log-level 6
  ipt -A UDT_FWD -i "$IF" -p udp -m multiport --dports 51820,500,4500,1194,1701,1723 -j DROP
  ipt -A UDT_FWD -i "$IF" -p tcp -m multiport --dports 1194,1723 -j DROP
  ipt -A UDT_FWD -i "$IF" -p 47 -j DROP     # GRE  (PPTP)
  ipt -A UDT_FWD -i "$IF" -p 50 -j DROP     # ESP  (IPsec)
  ipt -A UDT_FWD -i "$IF" -p 51 -j DROP     # AH   (IPsec)
  # BitTorrent handshake on otherwise-permitted ports
  ipt -A UDT_FWD -i "$IF" -m string --string "BitTorrent protocol" --algo bm \
      -j LOG --log-prefix "UDT-BT-BLOCK " --log-level 6 2>/dev/null
  ipt -A UDT_FWD -i "$IF" -m string --string "BitTorrent protocol" --algo bm -j DROP 2>/dev/null
  # authorized clients: web only
  ipt -A UDT_FWD -i "$IF" -m mark --mark $MARK -p tcp -m multiport --dports 80,443 -j ACCEPT
  # everything else from the AP dies here
  ipt -A UDT_FWD -i "$IF" -m limit --limit 10/min -j LOG --log-prefix "UDT-DROP " --log-level 6
  ipt -A UDT_FWD -i "$IF" -j DROP
  shape
}

# Three HTB classes per direction. Unknown clients land in the default (guest)
# class; the portal promotes a client by writing to $TIERS_FILE + tiers_apply.
shape() {
  tc qdisc del dev "$IF" root    2>/dev/null
  tc qdisc del dev "$IF" ingress 2>/dev/null
  tc qdisc add dev "$IF" root handle 1: htb default 10
  tc class add dev "$IF" parent 1:  classid 1:1  htb rate "$R_TRUSTED" ceil "$R_TRUSTED"
  tc class add dev "$IF" parent 1:1 classid 1:10 htb rate "$R_GUEST"    ceil "$R_GUEST"    burst 4k
  tc class add dev "$IF" parent 1:1 classid 1:20 htb rate "$R_STANDARD" ceil "$R_STANDARD" burst 8k
  tc class add dev "$IF" parent 1:1 classid 1:30 htb rate "$R_TRUSTED"  ceil "$R_TRUSTED"  burst 32k
  for c in 10 20 30; do
    tc qdisc add dev "$IF" parent 1:$c handle ${c}: sfq perturb 10 2>/dev/null
  done
  tc qdisc add dev "$IF" handle ffff: ingress
  tiers_apply
}

rate_for() {
  case "$1" in
    trusted)  echo "$R_TRUSTED" ;;
    standard) echo "$R_STANDARD" ;;
    *)        echo "$R_GUEST" ;;
  esac
}

class_for() {
  case "$1" in
    trusted)  echo 30 ;;
    standard) echo 20 ;;
    *)        echo 10 ;;
  esac
}

# Rebuild every per-client filter from the tier file. Cheap, and far easier to
# reason about than surgically deleting individual u32 handles.
tiers_apply() {
  tc filter del dev "$IF" parent 1:    2>/dev/null
  tc filter del dev "$IF" parent ffff: 2>/dev/null
  if [ -f "$TIERS_FILE" ]; then
    while read -r ip tier; do
      case "$ip" in ""|\#*) continue ;; esac
      cls=$(class_for "$tier"); rate=$(rate_for "$tier")
      # download: destination IP -> tier class
      tc filter add dev "$IF" protocol ip parent 1: prio 1 u32 \
         match ip dst "$ip"/32 flowid 1:"$cls" 2>/dev/null
      # upload: police by source IP at the same rate
      tc filter add dev "$IF" parent ffff: protocol ip prio 1 u32 \
         match ip src "$ip"/32 police rate "$rate" burst 20k drop flowid :1 2>/dev/null
    done < "$TIERS_FILE"
  fi
  # anyone unlisted is policed to guest rate on upload
  tc filter add dev "$IF" parent ffff: protocol ip prio 99 u32 match u32 0 0 \
     police rate "$R_GUEST" burst 10k drop flowid :1 2>/dev/null
}

set_tier() {
  ip_addr="$1"; tier="$2"
  mkdir -p "$(dirname "$TIERS_FILE")"; touch "$TIERS_FILE"
  grep -v "^$ip_addr " "$TIERS_FILE" > "$TIERS_FILE.new" 2>/dev/null || true
  echo "$ip_addr $tier" >> "$TIERS_FILE.new"
  mv "$TIERS_FILE.new" "$TIERS_FILE"
  tiers_apply
}

down() {
  tc qdisc del dev "$IF" root    2>/dev/null
  tc qdisc del dev "$IF" ingress 2>/dev/null
  flush_chains
  ip addr flush dev "$IF" 2>/dev/null
}

authorize()   { ipt -t mangle -C UDT_MARK -m mac --mac-source "$1" -j MARK --set-mark $MARK 2>/dev/null \
                || ipt -t mangle -A UDT_MARK -m mac --mac-source "$1" -j MARK --set-mark $MARK; }
deauthorize() { ipt -t mangle -D UDT_MARK -m mac --mac-source "$1" -j MARK --set-mark $MARK 2>/dev/null; }
list()        { ipt -t mangle -S UDT_MARK 2>/dev/null | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}'; }

case "${1:-up}" in
  up) up ;; down) down ;; shape) shape ;;
  authorize) authorize "$2" ;; deauthorize) deauthorize "$2" ;; list) list ;;
  tier) set_tier "$2" "$3" ;; tiers-apply) tiers_apply ;;
  *) echo "usage: $0 up|down|shape|authorize <MAC>|deauthorize <MAC>|list|tier <IP> <guest|standard|trusted>|tiers-apply" >&2; exit 1 ;;
esac
