#!/usr/bin/env python3
"""upside-down-ternet :: image-flipping HTTP proxy.

Sits behind squid as a parent proxy, so squid does the logging and this only
does the joke. Accepts both absolute-URI requests (how squid talks to a parent)
and origin-form requests (transparent interception), so it works either way.

Only cleartext HTTP is touched. HTTPS is never intercepted or decrypted -- doing
so would require planting a CA on every client, which this project refuses to do.
"""
import http.server, ipaddress, os, shutil, socket, subprocess, urllib.error, urllib.request

LISTEN = ("127.0.0.1", int(os.environ.get("UDT_FLIP_PORT", "3129")))
TIMEOUT = 20
MAXBYTES = 4 * 1024 * 1024


def _find_magick():
    """ImageMagick 7 (Debian 13+) ships 'magick'; ImageMagick 6 (Debian 12)
    ships only 'convert'. Both accept the same rotate invocation."""
    for cand in (os.environ.get("UDT_MAGICK"), shutil.which("magick"),
                 shutil.which("convert")):
        if cand and os.path.exists(cand):
            return cand
    return "convert"


MAGICK = _find_magick()
FMT = {"image/jpeg": "jpg", "image/jpg": "jpg", "image/png": "png",
       "image/gif": "gif", "image/bmp": "bmp", "image/webp": "webp"}
HOP = {"connection", "proxy-connection", "keep-alive", "transfer-encoding",
       "te", "trailer", "upgrade", "content-length", "content-encoding"}


def flip(data, fmt):
    try:
        p = subprocess.run([MAGICK, "-", "-rotate", "180", fmt + ":-"],
                           input=data, capture_output=True, timeout=25)
        if p.returncode == 0 and p.stdout:
            return p.stdout
    except Exception:
        pass
    return None


def is_internal(host):
    """Refuse anything resolving into RFC1918 / loopback so the proxy cannot be
    used as a bridge from the portal network into the operator's real LAN."""
    h = host.split(":")[0].strip("[]")
    try:
        infos = socket.getaddrinfo(h, None)
    except Exception:
        return True
    for i in infos:
        try:
            ip = ipaddress.ip_address(i[4][0])
        except Exception:
            return True
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    return False


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _url(self):
        # squid-as-parent sends "GET http://host/path"; interception sends "GET /path"
        if self.path.startswith("http://"):
            return self.path, self.path.split("/")[2]
        host = self.headers.get("Host")
        if not host:
            return None, None
        return "http://" + host + self.path, host

    def _relay(self, want_body):
        url, host = self._url()
        if not url:
            return self.send_error(400)
        if is_internal(host):
            return self.send_error(403, "Forbidden")
        body = None
        cl = self.headers.get("Content-Length")
        if cl and cl.isdigit():
            body = self.rfile.read(int(cl))
        req = urllib.request.Request(url, data=body, method=self.command)
        for k, v in self.headers.items():
            if k.lower() in HOP or k.lower() == "host":
                continue
            req.add_header(k, v)
        req.add_header("Accept-Encoding", "identity")
        try:
            r = urllib.request.urlopen(req, timeout=TIMEOUT)
            status, hdrs, data = r.status, r.headers, r.read(MAXBYTES)
            r.close()
        except urllib.error.HTTPError as e:
            status, hdrs, data = e.code, e.headers, e.read(MAXBYTES)
        except Exception:
            return self.send_error(502, "Bad Gateway")

        ctype = (hdrs.get("Content-Type") or "").split(";")[0].strip().lower()
        if want_body and ctype in FMT and data:
            out = flip(data, FMT[ctype])
            if out:
                data = out

        self.send_response(status)
        for k, v in hdrs.items():
            if k.lower() in HOP:
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        if want_body:
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass
        self.close_connection = True

    def do_GET(self):
        self._relay(True)

    def do_POST(self):
        self._relay(True)

    def do_HEAD(self):
        self._relay(False)


class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = socket.AF_INET


if __name__ == "__main__":
    S(LISTEN, H).serve_forever()
