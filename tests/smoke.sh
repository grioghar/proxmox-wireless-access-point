#!/bin/bash
# upside-down-ternet :: smoke test
#
# Exercises everything that does not require a radio: config rendering, the
# captive portal (page, field validation, consent rejection) and the image
# flipper. Run inside the container:
#
#   docker run --rm -v $PWD/udt.conf:/etc/udt/udt.conf:ro \
#       --entrypoint bash udt-test:latest /opt/udt/smoke.sh
set -u
PASS=0; FAIL=0
ok(){ echo "  PASS  $*"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
has(){ grep -q "$1" "$2" && ok "$3" || no "$3"; }

echo "== config rendering =="
. /etc/udt/udt.conf
render(){ sed -e "s|__IFACE__|${UDT_IFACE}|g" -e "s|__SSID__|${UDT_SSID}|g" \
  -e "s|__HW_MODE__|${UDT_HW_MODE}|g" -e "s|__CHANNEL__|${UDT_CHANNEL}|g" \
  -e "s|__GW__|${UDT_GW}|g" -e "s|__NET__|${UDT_NET}|g" \
  -e "s|__DHCP_START__|${UDT_DHCP_START}|g" -e "s|__DHCP_END__|${UDT_DHCP_END}|g" \
  -e "s|__DNS1__|${UDT_DNS1}|g" -e "s|__DNS2__|${UDT_DNS2}|g" \
  -e "s|__FLIP_PORT__|3129|g" "$1"; }
render /opt/udt/templates/squid.conf.tmpl   > /etc/squid/squid.conf
render /opt/udt/templates/dnsmasq.conf.tmpl > /etc/dnsmasq-udt.conf
render /opt/udt/templates/hostapd.conf.tmpl > /etc/hostapd.conf

squid -k parse -f /etc/squid/squid.conf >/dev/null 2>&1 && ok "squid config parses" || no "squid config parses"
dnsmasq --test -C /etc/dnsmasq-udt.conf >/dev/null 2>&1 && ok "dnsmasq config parses" || no "dnsmasq config parses"
has "^ap_isolate=1" /etc/hostapd.conf "hostapd enables client isolation"

echo "== captive portal =="
mkdir -p /var/lib/udt
python3 /opt/udt/portal.py & PP=$!
sleep 3
UA='Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1'
curl -s --max-time 10 -H "User-Agent: $UA" http://127.0.0.1:8080/ -o /tmp/p.html
[ -s /tmp/p.html ] && ok "portal serves a page ($(stat -c%s /tmp/p.html) bytes)" || no "portal serves a page"
has "Never connect to an open internet access point" /tmp/p.html "warning banner present"
has 'name="name"'  /tmp/p.html "name field present"
has 'name="email"' /tmp/p.html "email field present"
has 'name="phone"' /tmp/p.html "phone field present"
has 'name="agree"' /tmp/p.html "consent checkbox present"
has "an iPhone" /tmp/p.html "user-agent OS detected"
has "Safari"    /tmp/p.html "user-agent browser detected"

curl -s --max-time 10 -X POST http://127.0.0.1:8080/consent \
     -d "name=Test&email=t@example.com&phone=5551234" -o /tmp/r1.html
has "All fields are required" /tmp/r1.html "rejects submission without consent"

curl -s --max-time 10 -X POST http://127.0.0.1:8080/consent \
     -d "name=Test&email=notanemail&phone=5551234&agree=1" -o /tmp/r2.html
has "look valid" /tmp/r2.html "rejects malformed email"
kill $PP 2>/dev/null

echo "== image flipper =="
python3 /opt/udt/flipproxy.py & FP=$!
sleep 2
IMG=http://www.textfiles.com/images/textfile.gif
curl -s --max-time 20 "$IMG" -o /tmp/d.gif
curl -s --max-time 25 -x http://127.0.0.1:3129 "$IMG" -o /tmp/v.gif
if [ -s /tmp/d.gif ] && [ -s /tmp/v.gif ]; then
  magick /tmp/d.gif -rotate 180 /tmp/e.gif 2>/dev/null
  A=$(magick /tmp/v.gif -depth 8 rgb:- 2>/dev/null | md5sum | cut -d' ' -f1)
  B=$(magick /tmp/e.gif -depth 8 rgb:- 2>/dev/null | md5sum | cut -d' ' -f1)
  [ -n "$A" ] && [ "$A" = "$B" ] && ok "proxied image is a pixel-exact 180-degree rotation" \
    || no "proxied image is a pixel-exact 180-degree rotation"
else
  echo "  SKIP  flipper (no outbound HTTP available)"
fi
C=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -x http://127.0.0.1:3129 http://192.168.1.1/)
[ "$C" = "403" ] && ok "proxy refuses RFC1918 destinations (403)" || no "proxy refuses RFC1918 (got $C)"
kill $FP 2>/dev/null

echo
echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
