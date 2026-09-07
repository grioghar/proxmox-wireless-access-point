#!/usr/bin/env python3
"""upside-down-ternet :: captive portal + consent ledger.

Every client is unauthorized until it submits the consent form. On submit we
record identity + device fingerprint and mark the MAC in iptables, which is what
actually grants HTTP/HTTPS egress.

NOTE ON "$USER": browsers cannot read the OS username -- there is no such API,
by design. The closest real signal is the DHCP hostname the device volunteers
(often "Someones-iPhone"), which we read from the dnsmasq lease file.
"""
import html, os, re, sqlite3, subprocess, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CONF = os.environ.get("UDT_CONF", "/etc/udt/udt.conf")
CFG = {}
if os.path.exists(CONF):
    for line in open(CONF):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            CFG[k.strip()] = v.strip()

DB_PATH = os.environ.get("UDT_DB", "/var/lib/udt/udt.db")
LEASES = os.environ.get("UDT_LEASES", "/var/lib/udt/dnsmasq.leases")
NETSH = os.environ.get("UDT_NETSH", "/opt/udt/udt-net.sh")
RETENTION = int(CFG.get("UDT_RETENTION_DAYS", "30") or 0)
SSID = CFG.get("UDT_SSID", "upside-down-ternet")
PORT = 8080

OUI = {
    "00:1a:11": "Google", "3c:5a:b4": "Google", "f4:f5:d8": "Google",
    "00:03:93": "Apple", "a4:5e:60": "Apple", "f0:18:98": "Apple",
    "ac:bc:32": "Apple", "dc:a9:04": "Apple", "8c:85:90": "Apple",
    "00:1d:7e": "Cisco", "00:16:6c": "Samsung", "5c:0a:5b": "Samsung",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "00:50:56": "VMware", "52:54:00": "QEMU/KVM", "e0:2e:0b": "Intel",
}


def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.execute("""CREATE TABLE IF NOT EXISTS clients(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, mac TEXT, ip TEXT,
        hostname TEXT, vendor TEXT, name TEXT, email TEXT, phone TEXT,
        agreed INTEGER, user_agent TEXT, accept_language TEXT, fingerprint TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, mac TEXT, ip TEXT,
        kind TEXT, detail TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS tiers(
        mac TEXT PRIMARY KEY, tier TEXT NOT NULL, note TEXT)""")
    return c


def prune():
    if RETENTION <= 0:
        return
    cutoff = time.strftime("%Y-%m-%dT%H:%M:%S",
                           time.localtime(time.time() - RETENTION * 86400))
    c = db()
    c.execute("DELETE FROM clients WHERE ts < ?", (cutoff,))
    c.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
    c.commit(); c.close()


def mac_for_ip(ip):
    try:
        out = subprocess.run(["ip", "neigh", "show", ip], capture_output=True,
                             text=True, timeout=5).stdout
        m = re.search(r"lladdr ([0-9a-f:]{17})", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    try:
        for line in open("/proc/net/arp").readlines()[1:]:
            f = line.split()
            if len(f) >= 4 and f[0] == ip and f[3] != "00:00:00:00:00:00":
                return f[3]
    except Exception:
        pass
    return None


def lease_hostname(mac, ip):
    try:
        for line in open(LEASES):
            f = line.split()
            if len(f) >= 4 and (f[1] == mac or f[2] == ip):
                return None if f[3] == "*" else f[3]
    except Exception:
        pass
    return None


def vendor(mac):
    return OUI.get(mac[:8].lower(), "unknown") if mac else "unknown"


def friendly(hostname):
    """Turn 'Steves-iPhone' / 'johns-laptop.local' into something greetable."""
    if not hostname:
        return None
    h = hostname.split(".")[0].replace("_", "-")
    # "Steve's-iPhone" -> Steve. Note we do NOT strip a bare trailing "s":
    # that would turn Chris into Chri and Thomas into Thoma.
    m = re.match(r"^([A-Za-z]{2,20})['’]s?[-]", h)
    if m:
        return m.group(1).capitalize()
    m = re.match(r"^([A-Za-z]{2,20})-", h)
    if m:
        return m.group(1).capitalize()
    if re.match(r"^[A-Za-z]{2,20}$", h):
        return h.capitalize()
    return None


def describe_ua(ua):
    ua = ua or ""
    os_ = "an unidentified system"
    for pat, name in [(r"Windows NT 10", "Windows"), (r"Windows NT", "Windows"),
                      (r"iPhone", "an iPhone"), (r"iPad", "an iPad"),
                      (r"Mac OS X|Macintosh", "a Mac"), (r"Android", "Android"),
                      (r"CrOS", "a Chromebook"), (r"Linux", "Linux")]:
        if re.search(pat, ua):
            os_ = name
            break
    br = "a browser"
    for pat, name in [(r"Edg/", "Edge"), (r"OPR/", "Opera"), (r"Firefox/", "Firefox"),
                      (r"Chrome/", "Chrome"), (r"Safari/", "Safari")]:
        if re.search(pat, ua):
            br = name
            break
    return os_, br


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%(ssid)s</title><style>
*{box-sizing:border-box}
body{margin:0;background:#0d1117;color:#e6edf3;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:560px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:#8b949e;font-size:13px;margin-bottom:22px}
.warn{border:1px solid #f85149;background:#2d1214;border-radius:10px;padding:16px 18px;margin:0 0 22px}
.warn b{color:#ff9d95;display:block;margin-bottom:6px;font-size:15px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px 18px;margin-bottom:20px}
.card h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#8b949e;margin:0 0 12px}
.row{display:flex;justify-content:space-between;gap:14px;padding:5px 0;border-bottom:1px solid #21262d;font-size:13px}
.row:last-child{border-bottom:0}
.row span:first-child{color:#8b949e}
.row span:last-child{text-align:right;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
label{display:block;font-size:13px;color:#8b949e;margin:14px 0 5px}
input[type=text],input[type=email],input[type=tel]{width:100%%;padding:10px 12px;border-radius:7px;
  border:1px solid #30363d;background:#0d1117;color:#e6edf3;font-size:15px}
input:focus{outline:2px solid #1f6feb;border-color:#1f6feb}
.agree{display:flex;gap:10px;align-items:flex-start;margin:20px 0 8px;font-size:13px;color:#c9d1d9}
.agree input{margin-top:3px;width:17px;height:17px;flex:none}
button{width:100%%;margin-top:18px;padding:12px;border:0;border-radius:7px;background:#238636;
  color:#fff;font-size:15px;font-weight:600;cursor:pointer}
.err{color:#ff9d95;font-size:13px;margin-top:10px}
</style></head><body><div class="wrap">
<h1>Hey %(greeting)s</h1>
<div class="sub">You are connected to <b>%(ssid)s</b>, an open wireless network.</div>

<div class="warn"><b>Never connect to an open internet access point.</b>
All traffic through here is monitored. You have no idea who runs this network, and
neither does your device. Everything below was collected before you typed anything.</div>

<div class="card"><h2>What this network already knows</h2>
%(facts)s
<div class="row"><span>Sites you visit</span><span>logged by domain</span></div>
</div>

<form method="POST" action="/consent" id="f">
<div class="card"><h2>Sign in to continue</h2>
<label for="n">Full name</label><input type="text" id="n" name="name" required autocomplete="name">
<label for="e">Email address</label><input type="email" id="e" name="email" required autocomplete="email">
<label for="p">Phone number</label><input type="tel" id="p" name="phone" required autocomplete="tel">
<div class="agree"><input type="checkbox" id="a" name="agree" value="1" required>
<label for="a" style="margin:0;color:#c9d1d9">I understand that all of my activity on this
network is monitored, recorded and retained, and I consent to it.</label></div>
<button type="submit" id="b">Agree &amp; connect</button>
%(error)s
</div>
<input type="hidden" name="fp" id="fp">
</form>

<div class="sub" style="margin-top:24px">Records are retained for %(retention)s.</div>
</div>
<script>
(function(){
  var d={};
  try{
    d.screen=screen.width+"x"+screen.height+"@"+(window.devicePixelRatio||1);
    d.tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
    d.lang=navigator.languages?navigator.languages.join(","):navigator.language;
    d.cores=navigator.hardwareConcurrency||null;
    d.mem=navigator.deviceMemory||null;
    d.touch=navigator.maxTouchPoints||0;
    d.platform=navigator.platform||null;
    var c=document.createElement("canvas"),g=c.getContext("webgl");
    if(g){var x=g.getExtension("WEBGL_debug_renderer_info");
      if(x){d.gpu=g.getParameter(x.UNMASKED_RENDERER_WEBGL);}}
  }catch(e){}
  document.getElementById("fp").value=JSON.stringify(d);
})();
</script></body></html>"""

DONE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Connected</title>
<style>body{margin:0;background:#0d1117;color:#e6edf3;font:15px/1.6 -apple-system,sans-serif}
.w{max-width:520px;margin:0 auto;padding:60px 22px}h1{font-size:21px}
.c{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;margin-top:20px;font-size:14px}
b{color:#7ee787}</style></head><body><div class="w">
<h1>You're connected, %(name)s.</h1>
<div class="c">Your session is capped at <b>%(rate)s</b>.<br><br>
Everything you do from here is attributed to the name, email and phone number you
just entered, and to this device. That is exactly how much a stranger's open
network can learn about you in under a minute.</div></div></body></html>"""


class Portal(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "udt"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _client(self):
        ip = self.client_address[0]
        mac = mac_for_ip(ip)
        host = lease_hostname(mac, ip) if mac else None
        return ip, mac, host

    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        b = body.encode("utf-8", "replace")
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

    def _render(self, error=""):
        ip, mac, host = self._client()
        ua = self.headers.get("User-Agent", "")
        os_, br = describe_ua(ua)
        greet = friendly(host) or "there"
        rows = [("Your device name", host or "not advertised"),
                ("Hardware address", mac or "unknown"),
                ("Device vendor", vendor(mac)),
                ("Local address", ip),
                ("Operating system", os_),
                ("Browser", br),
                ("Preferred language",
                 self.headers.get("Accept-Language", "unknown").split(",")[0])]
        facts = "".join('<div class="row"><span>%s</span><span>%s</span></div>'
                        % (html.escape(k), html.escape(str(v))) for k, v in rows)
        ret = ("%d days" % RETENTION) if RETENTION > 0 else "as long as this network runs"
        err = '<div class="err">%s</div>' % html.escape(error) if error else ""
        self._send(PAGE % {"ssid": html.escape(SSID), "greeting": html.escape(greet),
                           "facts": facts, "error": err, "retention": ret})

    def do_GET(self):
        self._render()

    def do_POST(self):
        if urlparse(self.path).path != "/consent":
            return self._render()
        n = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))

        def get(k):
            return (form.get(k, [""])[0] or "").strip()

        name, email, phone = get("name"), get("email"), get("phone")
        if not (name and email and phone and get("agree")):
            return self._render("All fields are required, including consent.")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", email):
            return self._render("That email address doesn't look valid.")

        ip, mac, host = self._client()
        if not mac:
            return self._render("Could not identify your device. Reconnect and retry.")

        c = db()
        c.execute("""INSERT INTO clients(ts,mac,ip,hostname,vendor,name,email,phone,
                     agreed,user_agent,accept_language,fingerprint)
                     VALUES(?,?,?,?,?,?,?,?,1,?,?,?)""",
                  (time.strftime("%Y-%m-%dT%H:%M:%S"), mac, ip, host, vendor(mac),
                   name, email, phone, self.headers.get("User-Agent", ""),
                   self.headers.get("Accept-Language", ""), get("fp")))
        # An operator may have pre-assigned this device a better tier.
        row = c.execute("SELECT tier FROM tiers WHERE mac=?", (mac,)).fetchone()
        tier = row[0] if row else "guest"
        c.commit(); c.close()

        subprocess.run([NETSH, "authorize", mac], timeout=10, capture_output=True)
        subprocess.run([NETSH, "tier", ip, tier], timeout=10, capture_output=True)
        prune()
        rate = {"trusted": CFG.get("UDT_RATE_TRUSTED", "100mbit"),
                "standard": CFG.get("UDT_RATE_STANDARD", "5mbit")}.get(
                    tier, CFG.get("UDT_RATE", "128kbit"))
        self._send(DONE % {"name": html.escape(name), "rate": html.escape(rate)})


def main():
    db().close()
    prune()
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer(("0.0.0.0", PORT), Portal).serve_forever()


if __name__ == "__main__":
    main()
