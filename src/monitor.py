#!/usr/bin/env python3
"""upside-down-ternet :: live operator dashboard.

Shows every associated station with its signal, throughput, classification and
whatever identity the consent ledger holds.

SECURITY: this page exposes names, emails, phone numbers and browsing activity,
so it deliberately binds to the UPLINK address only -- never to the AP interface.
A device on the AP cannot reach it. udt-net.sh also drops wlo1 traffic aimed at
this port as a second line of defence.
"""
import html, json, os, re, socket, sqlite3, subprocess, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONF = os.environ.get("UDT_CONF", "/etc/udt/udt.conf")
CFG = {}
if os.path.exists(CONF):
    for line in open(CONF):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            CFG[k.strip()] = v.strip()

IFACE = CFG.get("UDT_IFACE", "wlan0")
UPLINK = CFG.get("UDT_UPLINK", "eth0")
SSID = CFG.get("UDT_SSID", "upside-down-ternet")
CHANNEL = CFG.get("UDT_CHANNEL", "?")
PORT = int(CFG.get("UDT_MONITOR_PORT", "8090") or 8090)
DB_PATH = os.environ.get("UDT_DB", "/var/lib/udt/udt.db")
LEASES = os.environ.get("UDT_LEASES", "/var/lib/udt/dnsmasq.leases")
TIERS = os.environ.get("UDT_TIERS", "/var/lib/udt/tiers")
SQUID_LOG = "/var/log/squid/access.log"
RATES = {"guest": CFG.get("UDT_RATE", "128kbit"),
         "standard": CFG.get("UDT_RATE_STANDARD", "5mbit"),
         "trusted": CFG.get("UDT_RATE_TRUSTED", "100mbit")}

OUI = {
    "00:1a:11": "Google", "3c:5a:b4": "Google", "f4:f5:d8": "Google",
    "00:03:93": "Apple", "a4:5e:60": "Apple", "f0:18:98": "Apple",
    "ac:bc:32": "Apple", "dc:a9:04": "Apple", "8c:85:90": "Apple",
    "00:1d:7e": "Cisco", "00:16:6c": "Samsung", "5c:0a:5b": "Samsung",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "00:50:56": "VMware", "52:54:00": "QEMU/KVM", "e0:2e:0b": "Intel",
    "bc:24:11": "Proxmox", "18:b4:30": "Nest", "cc:8c:bf": "Tuya",
}


def sh(cmd, timeout=6):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout).stdout
    except Exception:
        return ""


def uplink_ip():
    if CFG.get("UDT_MONITOR_BIND"):
        return CFG["UDT_MONITOR_BIND"]
    out = sh(["ip", "-4", "-o", "addr", "show", "dev", UPLINK])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    # last resort: whatever address reaches the default route
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def vendor(mac):
    return OUI.get((mac or "")[:8].lower(), "")


def stations():
    """Parse `iw station dump` into per-MAC radio stats."""
    out = sh(["iw", "dev", IFACE, "station", "dump"])
    res, cur = {}, None
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"^Station ([0-9a-f:]{17})", line)
        if m:
            cur = m.group(1)
            res[cur] = {"mac": cur}
            continue
        if not cur or ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        d = res[cur]
        if k == "signal":
            d["signal"] = int(re.sub(r"[^\-0-9].*$", "", v) or 0)
        elif k == "rx bytes":
            d["rx"] = int(v)
        elif k == "tx bytes":
            d["tx"] = int(v)
        elif k == "tx bitrate":
            d["bitrate"] = v.split(" ")[0] + " Mb/s"
        elif k == "connected time":
            d["connected"] = int(v.split(" ")[0])
        elif k == "inactive time":
            d["inactive"] = int(v.split(" ")[0])
    return res


def leases():
    out = {}
    try:
        for line in open(LEASES):
            f = line.split()
            if len(f) >= 4:
                out[f[1].lower()] = {"ip": f[2],
                                     "hostname": None if f[3] == "*" else f[3]}
    except Exception:
        pass
    return out


def marks():
    """MAC -> classification, straight from the live firewall."""
    out = {}
    for line in sh(["iptables", "-t", "mangle", "-S", "UDT_MARK"]).splitlines():
        m = re.search(r"--mac-source ([0-9A-Fa-f:]{17}).*--set-xmark (0x[0-9a-f]+)", line)
        if m:
            mac, mk = m.group(1).lower(), int(m.group(2), 16)
            out[mac] = {"authorized": bool(mk & 0x80), "mitm": bool(mk & 0x04)}
    return out


def tiers():
    out = {}
    try:
        for line in open(TIERS):
            f = line.split()
            if len(f) == 2:
                out[f[0]] = f[1]
    except Exception:
        pass
    return out


def identities():
    out = {}
    try:
        c = sqlite3.connect("file:%s?mode=ro" % DB_PATH, uri=True, timeout=5)
        for mac, name, email, phone, ts in c.execute(
                "SELECT mac,name,email,phone,ts FROM clients ORDER BY id"):
            if mac:
                out[mac.lower()] = {"name": name, "email": email,
                                    "phone": phone, "since": ts}
        c.close()
    except Exception:
        pass
    return out


def recent_domains(limit_lines=4000):
    """Tail squid's log and collect recent hostnames per client IP."""
    out = {}
    try:
        size = os.path.getsize(SQUID_LOG)
        with open(SQUID_LOG, "rb") as fh:
            fh.seek(max(0, size - 400000))
            lines = fh.read().decode("utf-8", "replace").splitlines()[-limit_lines:]
        for line in lines:
            f = line.split()
            if len(f) < 6:
                continue
            ip, url = f[1], f[5]
            host = url.split("//")[-1].split("/")[0].split(":")[0]
            if not host or host == "-":
                continue
            d = out.setdefault(ip, {})
            d[host] = d.get(host, 0) + 1
    except Exception:
        pass
    return {ip: sorted(d.items(), key=lambda kv: -kv[1])[:6] for ip, d in out.items()}


def snapshot():
    st, ls, mk, tr, ident, doms = (stations(), leases(), marks(), tiers(),
                                   identities(), recent_domains())
    rows = []
    for mac, s in st.items():
        lease = ls.get(mac, {})
        ip = lease.get("ip")
        m = mk.get(mac, {})
        tier = tr.get(ip, "guest") if ip else "guest"
        idn = ident.get(mac, {})
        rows.append({
            "mac": mac, "ip": ip, "hostname": lease.get("hostname"),
            "vendor": vendor(mac), "signal": s.get("signal"),
            "rx": s.get("rx", 0), "tx": s.get("tx", 0),
            "bitrate": s.get("bitrate"), "connected": s.get("connected", 0),
            "inactive": s.get("inactive", 0),
            "authorized": m.get("authorized", False), "mitm": m.get("mitm", False),
            "tier": tier, "cap": RATES.get(tier, "?"),
            "name": idn.get("name"), "email": idn.get("email"),
            "phone": idn.get("phone"),
            "domains": doms.get(ip, []) if ip else [],
        })
    rows.sort(key=lambda r: (r["signal"] is None, -(r["signal"] or -999)))
    return {"ts": time.time(), "ssid": SSID, "channel": CHANNEL,
            "iface": IFACE, "count": len(rows), "stations": rows}


MITM_LOG = "/var/lib/udt/mitm-requests.log"
TEMPLATE = "/opt/udt/templates/monitor.html"


def _tail(path, nbytes=600000):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            fh.seek(max(0, size - nbytes))
            data = fh.read().decode("utf-8", "replace")
        return data.splitlines()[1:] if size > nbytes else data.splitlines()
    except Exception:
        return []


def requests_log(client=None, since=0.0, limit=400, q=None):
    """Merge squid's access log with the mitm addon's, newest last.

    Two sources because they are mutually exclusive: squid handles guests, the
    addon handles intercepted devices, and neither sees the other's traffic.
    """
    rows = []
    for line in _tail(SQUID_LOG):
        f = line.split()
        if len(f) < 8:
            continue
        try:
            ts = float(f[0])
        except ValueError:
            continue
        url = f[5]
        host = url.split("//")[-1].split("/")[0]
        rows.append({"ts": ts, "ip": f[1], "method": f[4], "url": url,
                     "host": host, "status": f[6], "bytes": f[7], "via": "squid"})
    for line in _tail(MITM_LOG):
        f = line.rstrip("\n").split("\t")
        if len(f) < 6:
            continue
        try:
            ts = float(f[0])
        except ValueError:
            continue
        url = f[3]
        host = url.split("//")[-1].split("/")[0]
        rows.append({"ts": ts, "ip": f[1], "method": f[2], "url": url,
                     "host": host, "status": f[4], "bytes": f[5],
                     "via": f[6] if len(f) > 6 else "mitm"})

    if client and client != "all":
        rows = [r for r in rows if r["ip"] == client]
    if since:
        rows = [r for r in rows if r["ts"] > since]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["url"].lower()]
    rows.sort(key=lambda r: r["ts"])
    return rows[-limit:]


def known_clients():
    """Every client that has ever appeared, so the drop-down has history even
    for devices that are not associated right now."""
    seen = {}
    for mac, l in leases().items():
        if l.get("ip"):
            seen[l["ip"]] = l.get("hostname") or vendor(mac) or l["ip"]
    for r in requests_log(limit=6000):
        seen.setdefault(r["ip"], r["ip"])
    return [{"ip": ip, "label": lab} for ip, lab in
            sorted(seen.items(), key=lambda kv: kv[1].lower())]


class Mon(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "udt-monitor"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, body, ctype="application/json", code=200):
        b = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(b)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        one = lambda k, d=None: (qs.get(k, [d])[0])
        if u.path == "/api/stations":
            return self._send(json.dumps(snapshot()))
        if u.path == "/api/requests":
            try:
                since = float(one("since", "0") or 0)
            except ValueError:
                since = 0.0
            try:
                limit = min(2000, int(one("limit", "400") or 400))
            except ValueError:
                limit = 400
            return self._send(json.dumps({
                "ts": time.time(),
                "clients": known_clients(),
                "rows": requests_log(one("client"), since, limit, one("q")),
            }))
        try:
            page = open(TEMPLATE).read()
        except OSError:
            return self._send("monitor template missing", "text/plain", 500)
        page = (page.replace("__SSID__", html.escape(SSID))
                    .replace("__CHANNEL__", html.escape(str(CHANNEL)))
                    .replace("__IFACE__", html.escape(IFACE)))
        return self._send(page, "text/html; charset=utf-8")


TLS_CERT = CFG.get("UDT_MONITOR_TLS_CERT", "")
TLS_KEY = CFG.get("UDT_MONITOR_TLS_KEY", "")
HOSTNAME = CFG.get("UDT_MONITOR_HOSTNAME", "")
REDIRECT = CFG.get("UDT_MONITOR_REDIRECT", "0") == "1"
REDIRECT_PORT = int(CFG.get("UDT_MONITOR_REDIRECT_PORT", "80") or 80)


class Redirect(BaseHTTPRequestHandler):
    """Plain-HTTP listener that sends everyone to the HTTPS dashboard."""
    protocol_version = "HTTP/1.1"
    server_version = "udt-monitor"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _go(self):
        host = HOSTNAME or self.headers.get("Host", "").split(":")[0] or uplink_ip()
        port = "" if PORT == 443 else ":%d" % PORT
        self.send_response(301)
        self.send_header("Location", "https://%s%s%s" % (host, port, self.path))
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    do_GET = do_HEAD = do_POST = _go


def start_redirect(bind):
    import threading
    try:
        srv = ThreadingHTTPServer((bind, REDIRECT_PORT), Redirect)
    except OSError as e:
        print("[udt] WARNING: redirect listener on %s:%d failed (%s)"
              % (bind, REDIRECT_PORT, e), flush=True)
        return
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print("[udt] redirecting http://%s:%d/ -> https://%s:%d/"
          % (bind, REDIRECT_PORT, HOSTNAME or bind, PORT), flush=True)


def main():
    bind = uplink_ip()
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer.allow_reuse_address = True
    srv = ThreadingHTTPServer((bind, PORT), Mon)

    scheme = "http"
    if TLS_CERT and TLS_KEY:
        if not (os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY)):
            print("[udt] WARNING: UDT_MONITOR_TLS_CERT/KEY set but missing on disk; "
                  "serving plain HTTP", flush=True)
        else:
            try:
                import ssl
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(TLS_CERT, TLS_KEY)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
                scheme = "https"
            except Exception as e:
                print("[udt] WARNING: could not enable TLS (%s); serving plain HTTP"
                      % e, flush=True)

    where = HOSTNAME or bind
    print("[udt] monitor on %s://%s:%d/ (uplink only, not reachable from %s)"
          % (scheme, where, PORT, IFACE), flush=True)
    # Only meaningful once TLS is actually on; redirecting to a scheme we do not
    # serve would just loop the browser.
    if REDIRECT and scheme == "https":
        start_redirect(bind)
    elif REDIRECT:
        print("[udt] WARNING: UDT_MONITOR_REDIRECT is on but TLS is not; "
              "not starting a redirect that would loop", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
