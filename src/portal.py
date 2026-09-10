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


def _cfg_value(raw):
    """Reduce one `KEY=` right-hand side to the value bash would see: drop a
    trailing ` # comment`, then strip the shell quoting.

    entrypoint.sh `source`s this same file, so both halves matter. Unquoted
    `UDT_SIGNUP_LABEL=my Plex server` sets the label to "my" and then makes
    bash try to run `Plex`; an inline comment bash ignores would otherwise end
    up inside the value on this side.

    One deliberate divergence: for a legacy unquoted `KEY=two words` bash keeps
    only "two" (and tries to run the rest), while this returns the whole string.
    Being forgiving on the read side is more useful than reproducing the bug.
    """
    out, quote = [], ""
    for i, ch in enumerate(raw):
        if quote:
            out.append(ch)
            if ch == quote and (quote == "'" or raw[i - 1] != "\\"):
                quote = ""
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#" and i and raw[i - 1].isspace():
            break
        else:
            out.append(ch)
    v = "".join(out).strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        q, v = v[0], v[1:-1]
        if q == '"':
            v = re.sub(r'\\([$`"\\])', r"\1", v)
    return v


CFG = {}
if os.path.exists(CONF):
    for line in open(CONF):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            CFG[k.strip()] = _cfg_value(v)

DB_PATH = os.environ.get("UDT_DB", "/var/lib/udt/udt.db")
LEASES = os.environ.get("UDT_LEASES", "/var/lib/udt/dnsmasq.leases")
NETSH = os.environ.get("UDT_NETSH", "/opt/udt/udt-net.sh")
RETENTION = int(CFG.get("UDT_RETENTION_DAYS", "30") or 0)
SSID = CFG.get("UDT_SSID", "upside-down-ternet")
PORT = 8080

MITM_ENABLED = CFG.get("UDT_MITM", "0") == "1"
# Auto-promote: the portal silently probes the check endpoint on load. A device
# that trusts the CA is moved to the trusted tier without anyone clicking, which
# also authorizes it (it skips the consent form -- installing the CA on a device
# is already a deliberate act by its owner). Devices that fail the probe notice
# nothing and stay on the guest path.
MITM_AUTO = CFG.get("UDT_MITM_AUTO", "0") == "1"
MITM_HOST = CFG.get("UDT_MITM_CHECK_HOST", "mitm-check.udt")
MITM_CPORT = CFG.get("UDT_MITM_CHECK_PORT", "8443")
MITM_CA = os.environ.get("UDT_MITM_CA", "/var/lib/udt/mitm/mitmproxy-ca-cert.pem")
MITM_VERIFIED = os.environ.get("UDT_MITM_VERIFIED", "/var/lib/udt/mitm-verified")
VERIFY_WINDOW = 600  # seconds a successful handshake stays valid as proof


SIGNUP_URL = CFG.get("UDT_SIGNUP_URL", "")
SIGNUP_LABEL = CFG.get("UDT_SIGNUP_LABEL", "the media server")
SIGNUP_TTL = 600
_signup_cache = {"ts": 0.0, "posters": [], "steps": [], "host": ""}


def signup_content(force=False):
    """Mirror the public signup page of another service onto the portal.

    Portal clients are firewalled away from the LAN, so they cannot fetch that
    site or its images themselves. We pull it here and proxy the artwork through
    our own origin.
    """
    if not SIGNUP_URL:
        return _signup_cache
    now = time.time()
    if not force and _signup_cache["ts"] and now - _signup_cache["ts"] < SIGNUP_TTL:
        return _signup_cache
    posters, steps, host = [], [], ""
    try:
        import urllib.parse
        import urllib.request
        host = urllib.parse.urlparse(SIGNUP_URL).netloc
        req = urllib.request.Request(SIGNUP_URL, headers={"User-Agent": "udt-portal"})
        page = urllib.request.urlopen(req, timeout=12).read().decode("utf-8", "replace")
        for m in re.finditer(
                r"background-image:\s*url\(['\"]?([^'\")]+)"
                r"|<img\b[^>]+src=['\"]([^'\"]+)", page):
            p = (m.group(1) or m.group(2)).replace("&amp;", "&")
            if p.startswith("/") and p not in posters:
                posters.append(p)
            if len(posters) >= 8:
                break
        # Steps come out of the real list markup. The previous version flattened
        # everything after the heading and split it on phrases from that site's
        # copy, with no end bound -- so when the page was redesigned the last
        # "step" swallowed the following card, escaped tags and all.
        m = re.search(r"<h2[^>]*>\s*How it works.*?</h2>(.{0,4000})", page, re.S)
        tail = m.group(1) if m else ""
        lst = re.search(r"<(ol|ul)\b[^>]*>(.*?)</\1>", tail, re.S)
        if lst:
            items = re.findall(r"<li\b[^>]*>(.*?)</li>", lst.group(2), re.S)
        else:
            # No list to work with. Stop at the next heading so we cannot run on
            # into unrelated markup, and break on paragraph boundaries.
            items = re.split(r"</p>|<br\s*/?>", re.split(r"<h[1-6]\b", tail)[0])
        for it in items:
            t = html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", it))).strip()
            if t:
                steps.append(t[:240])
        steps = steps[:3]
    except Exception:
        pass
    if posters or steps:
        _signup_cache.update(ts=now, posters=posters, steps=steps, host=host)
    return _signup_cache


def recently_verified(ip):
    """True only if this IP completed a real TLS handshake against the check
    endpoint recently. That handshake is impossible without trusting the CA, so
    it is the one piece of evidence we accept for enabling interception."""
    try:
        now = time.time()
        for line in open(MITM_VERIFIED):
            f = line.split()
            if len(f) == 2 and f[0] == ip and now - int(f[1]) < VERIFY_WINDOW:
                return True
    except Exception:
        pass
    return False

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
    # added later; migrate in place so existing ledgers keep working
    if "plex_signup" not in [r[1] for r in c.execute("PRAGMA table_info(clients)")]:
        c.execute("ALTER TABLE clients ADD COLUMN plex_signup INTEGER DEFAULT 0")
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
.su{margin-top:20px;padding-top:16px;border-top:1px solid #30363d}
.su h3{font-size:13px;margin:0 0 4px;color:#e6edf3}
.su p{font-size:12px;color:#8b949e;margin:0 0 10px;line-height:1.5}
.su ol{margin:0 0 12px;padding-left:18px;font-size:12px;color:#8b949e}
.su ol li{margin:4px 0}
.posters{display:grid;grid-template-columns:repeat(4,1fr);gap:7px;margin-bottom:12px}
.posters div{padding-top:150%%;background-size:cover;background-position:center;
  border-radius:5px;border:1px solid #30363d;
  transform:rotate(180deg)}
.su .agree{margin:12px 0 0}
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
%(signup)s
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
</script>
%(autoprobe)s
</body></html>"""

# Runs on page load. A TLS failure rejects the promise and we do nothing at all,
# so a device without the certificate never sees an error or a warning.
AUTOPROBE = """<script>
(function(){
  fetch("https://%(host)s:%(cport)s/check",{cache:"no-store"})
   .then(function(r){return r.json()})
   .then(function(){return fetch("/mitm/enable",{method:"POST"})})
   .then(function(r){ if(!r.ok) throw 0; return r.text(); })
   .then(function(){
      var b=document.createElement("div");
      b.className="card";
      b.style.borderColor="#238636";
      b.innerHTML="<b style='color:#7ee787'>Recognised device.</b> You have this "+
        "network's certificate installed, so you have been moved to full speed "+
        "&mdash; and your encrypted traffic is readable here. "+
        "<a href='/mitm' style='color:#58a6ff'>Manage or turn this off</a>.";
      var w=document.querySelector(".wrap"), f=document.querySelector("form");
      if(w&&f){w.insertBefore(b,f);}
   })
   .catch(function(){ /* no certificate: stay a guest, silently */ });
})();
</script>"""

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


MITM_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TLS interception</title><style>
body{margin:0;background:#0d1117;color:#e6edf3;font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.w{max-width:560px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:21px;margin:0 0 6px}
.sub{color:#8b949e;font-size:13px;margin-bottom:20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px 18px;margin-bottom:16px}
.warn{border-color:#d29922;background:#2a2011}
a.btn,button{display:block;width:100%%;text-align:center;text-decoration:none;margin-top:14px;
  padding:12px;border:0;border-radius:7px;font-size:15px;font-weight:600;cursor:pointer}
a.btn{background:#1f6feb;color:#fff}
button{background:#238636;color:#fff}
ol{padding-left:20px;font-size:14px;color:#c9d1d9}
li{margin:7px 0}
code{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:1px 5px;font-size:13px}
#s{margin-top:14px;font-size:14px}
.ok{color:#7ee787}.bad{color:#ff9d95}
</style></head><body><div class="w">
<h1>TLS interception</h1>
<div class="sub">Optional. Off unless you turn it on for this device.</div>

<div class="card warn"><b>What this does.</b> With the certificate below installed,
this network can read the full contents of your encrypted traffic — every URL,
every request body, every response. Without it, nothing here can touch your HTTPS;
you cannot be intercepted by accident. Install it only on a device you own and are
deliberately debugging, and remove it when you are done.</div>

<div class="card"><b>1. Install the certificate</b>
<a class="btn" href="/ca.crt">Download CA certificate</a>
<ol>
<li><b>iOS:</b> download, then Settings &rarr; Profile Downloaded &rarr; Install.
Then Settings &rarr; General &rarr; About &rarr; Certificate Trust Settings and
switch it on. iOS deliberately makes this two separate steps.</li>
<li><b>Android:</b> Settings &rarr; Security &rarr; Encryption &amp; credentials
&rarr; Install a certificate &rarr; CA certificate.</li>
<li><b>macOS:</b> open it in Keychain Access, then set it to Always Trust.</li>
<li><b>Windows:</b> install into <code>Trusted Root Certification Authorities</code>.</li>
</ol></div>

<div class="card"><b>2. Prove it worked</b>
<div class="sub" style="margin:6px 0 0">This fetches an HTTPS URL signed by that CA.
It can only succeed if your device really trusts it.</div>
<button id="v">Verify and enable for this device</button>
<div id="s"></div></div>

<div class="card"><b>Turn it back off</b>
<div class="sub" style="margin:6px 0 0">Stops interception for this device immediately.
Removing the certificate from your device is a separate step you should also do.</div>
<button id="d" style="background:#6e2c2c">Disable interception</button></div>
</div>
<script>
var S=document.getElementById("s");
document.getElementById("v").onclick=function(){
  S.textContent="Checking ...";S.className="";
  fetch("https://%(host)s:%(cport)s/check",{cache:"no-store"})
   .then(function(r){return r.json()})
   .then(function(){
      return fetch("/mitm/enable",{method:"POST"}).then(function(r){return r.text()})
        .then(function(t){S.textContent=t;S.className="ok"});
   })
   .catch(function(){
      S.innerHTML="Certificate is <b>not</b> trusted yet. Finish the install "+
                  "steps above (on iOS the Certificate Trust Settings toggle is "+
                  "the one people miss), then try again.";
      S.className="bad";
   });
};
document.getElementById("d").onclick=function(){
  fetch("/mitm/disable",{method:"POST"}).then(function(r){return r.text()})
   .then(function(t){S.textContent=t;S.className=""});
};
</script></body></html>"""


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
        probe = ""
        if MITM_ENABLED and MITM_AUTO:
            probe = AUTOPROBE % {"host": MITM_HOST, "cport": MITM_CPORT}
        self._send(PAGE % {"ssid": html.escape(SSID), "greeting": html.escape(greet),
                           "facts": facts, "error": err, "retention": ret,
                           "autoprobe": probe, "signup": self._signup_html()})

    def _signup_html(self):
        if not SIGNUP_URL:
            return ""
        c = signup_content()
        if not (c["posters"] or c["steps"]):
            return ""
        from urllib.parse import quote
        tiles = "".join(
            '<div style="background-image:url(/signupimg?p=%s)"></div>' % quote(p, safe="")
            for p in c["posters"][:8])
        steps = "".join("<li>%s</li>" % html.escape(s) for s in c["steps"])
        return (
            '<div class="su"><h3>While you are here &mdash; want in on %s?</h3>'
            '<p>Tick the box and I will pass your details along as an access '
            'request. Nothing else happens, and you can ignore this entirely.</p>'
            '%s%s'
            '<div class="agree"><input type="checkbox" id="ps" name="plex_signup" value="1">'
            '<label for="ps" style="margin:0;color:#c9d1d9">Yes, request access to %s '
            'for me using the details above.</label></div></div>'
            % (html.escape(SIGNUP_LABEL),
               ('<div class="posters">%s</div>' % tiles) if tiles else "",
               ("<ol>%s</ol>" % steps) if steps else "",
               html.escape(SIGNUP_LABEL)))

    def do_GET(self):
        p = urlparse(self.path).path
        if MITM_ENABLED and p == "/mitm":
            return self._send(MITM_PAGE % {"host": MITM_HOST, "cport": MITM_CPORT})
        if SIGNUP_URL and p == "/signupimg":
            # Proxy artwork from the signup site. Path-restricted and pinned to
            # that origin so this cannot be turned into an open relay.
            from urllib.parse import parse_qs, urlsplit, urlunsplit
            want = (parse_qs(urlparse(self.path).query).get("p", [""])[0] or "")
            if not want.startswith("/") or ".." in want:
                return self.send_error(400)
            base = urlsplit(SIGNUP_URL)
            target = urlunsplit((base.scheme, base.netloc, "", "", ""))
            try:
                import urllib.request
                r = urllib.request.urlopen(target + want, timeout=12)
                data, ctype = r.read(3 * 1024 * 1024), r.headers.get("Content-Type", "image/jpeg")
                r.close()
            except Exception:
                return self.send_error(502)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "max-age=600")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
            return
        if MITM_ENABLED and p == "/ca.crt":
            try:
                data = open(MITM_CA, "rb").read()
            except OSError:
                return self.send_error(404, "CA not generated yet")
            self.send_response(200)
            # this content type is what makes iOS/Android offer to install it
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Disposition", 'attachment; filename="udt-ca.crt"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True
            return
        self._render()

    def _mitm_toggle(self, on):
        ip, mac, _ = self._client()
        if not mac:
            return self._send("Could not identify this device.", 400, "text/plain")
        if on:
            if not recently_verified(ip):
                return self._send(
                    "Refused: this device has not proven it trusts the CA. "
                    "Install the certificate first.", 403, "text/plain")
            # promote/demote move both the iptables mark and the bandwidth tier,
            # so a trusted device gets full speed and a demoted one drops back
            # to the throttled, image-flipping guest path.
            subprocess.run([NETSH, "promote", ip], timeout=15, capture_output=True)
            msg = ("Interception ENABLED for %s, and this device is now on the "
                   "trusted tier at full speed." % mac)
        else:
            subprocess.run([NETSH, "demote", ip], timeout=15, capture_output=True)
            msg = ("Interception disabled for %s. Back to the guest tier: "
                   "throttled, spliced, images flipped." % mac)
        c = db()
        c.execute("INSERT INTO events(ts,mac,ip,kind,detail) VALUES(?,?,?,?,?)",
                  (time.strftime("%Y-%m-%dT%H:%M:%S"), mac, ip,
                   "mitm-on" if on else "mitm-off", msg))
        c.commit(); c.close()
        return self._send(msg, 200, "text/plain")

    def do_POST(self):
        p = urlparse(self.path).path
        if MITM_ENABLED and p == "/mitm/enable":
            return self._mitm_toggle(True)
        if MITM_ENABLED and p == "/mitm/disable":
            return self._mitm_toggle(False)
        if p != "/consent":
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
                     agreed,user_agent,accept_language,fingerprint,plex_signup)
                     VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?)""",
                  (time.strftime("%Y-%m-%dT%H:%M:%S"), mac, ip, host, vendor(mac),
                   name, email, phone, self.headers.get("User-Agent", ""),
                   self.headers.get("Accept-Language", ""), get("fp"),
                   1 if get("plex_signup") else 0))
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
