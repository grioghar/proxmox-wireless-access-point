FROM debian:trixie-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        hostapd dnsmasq squid-openssl iptables iproute2 iw wireless-regdb \
        imagemagick python3 openssl procps ca-certificates iputils-ping curl mitmproxy \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/udt /var/log/squid /var/run/hostapd /etc/udt

# hostapd/dnsmasq ship enabled units we never use; the entrypoint drives them.
RUN systemctl disable hostapd dnsmasq 2>/dev/null || true

COPY src/       /opt/udt/
COPY templates/ /opt/udt/templates/
RUN chmod +x /opt/udt/*.sh /opt/udt/*.py

# Dummy cert for squid's https_port. Splice mode never presents it to a client
# -- squid just requires a cert to open the port at all.
RUN openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem -days 3650 \
        -nodes -subj "/CN=upside-down-ternet" 2>/dev/null \
    && cat /tmp/k.pem /tmp/c.pem > /etc/squid/dummy.pem && rm -f /tmp/k.pem /tmp/c.pem \
    && chown proxy:proxy /etc/squid/dummy.pem && chmod 400 /etc/squid/dummy.pem

VOLUME ["/var/lib/udt", "/var/log/squid"]
ENTRYPOINT ["/opt/udt/entrypoint.sh"]
