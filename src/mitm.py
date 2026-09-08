#!/usr/bin/env python3
"""upside-down-ternet :: optional TLS interception support.

Two jobs:

  ensure-ca       make sure a mitmproxy CA exists in the shared confdir
  check-server    run the HTTPS endpoint that PROVES whether a client trusts it

The check server is the safety interlock. It serves a leaf certificate signed by
the mitmproxy CA on a name we control via our own DNS. If a client's fetch of
that URL succeeds, the client genuinely trusts the CA -- which can only happen if
someone deliberately installed and trusted it on that device. If the fetch fails,
the device is never intercepted. There is no override: this is what keeps
interception something a device owner opts into rather than something done to
them.
"""
import os, ssl, subprocess, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFDIR = os.environ.get("UDT_MITM_CONFDIR", "/var/lib/udt/mitm")
CA_PEM = os.path.join(CONFDIR, "mitmproxy-ca.pem")          # key + cert
CA_CERT = os.path.join(CONFDIR, "mitmproxy-ca-cert.pem")    # cert only
LEAF_KEY = os.path.join(CONFDIR, "check-leaf.key")
LEAF_CRT = os.path.join(CONFDIR, "check-leaf.crt")
VERIFIED = os.environ.get("UDT_MITM_VERIFIED", "/var/lib/udt/mitm-verified")
HOST = os.environ.get("UDT_MITM_CHECK_HOST", "mitm-check.udt")
PORT = int(os.environ.get("UDT_MITM_CHECK_PORT", "8443"))


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, timeout=60, **kw)


def ensure_ca():
    """mitmproxy generates its CA on first start; nudge it to do so headlessly."""
    os.makedirs(CONFDIR, exist_ok=True)
    if os.path.exists(CA_PEM):
        return True
    mitmdump = None
    for c in ("/usr/bin/mitmdump", "/usr/local/bin/mitmdump"):
        if os.path.exists(c):
            mitmdump = c
            break
    if not mitmdump:
        import shutil
        mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        print("mitmdump not installed", file=sys.stderr)
        return False
    p = subprocess.Popen([mitmdump, "--set", "confdir=" + CONFDIR, "-n", "-q"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        if os.path.exists(CA_PEM):
            break
        time.sleep(0.5)
    p.terminate()
    try:
        p.wait(timeout=10)
    except Exception:
        p.kill()
    return os.path.exists(CA_PEM)


def ensure_leaf():
    """Sign a leaf for the check hostname with the mitmproxy CA."""
    if os.path.exists(LEAF_CRT) and os.path.exists(LEAF_KEY):
        # regenerate monthly so an expiring leaf never silently breaks the gate
        if time.time() - os.path.getmtime(LEAF_CRT) < 30 * 86400:
            return True
    if not os.path.exists(CA_PEM):
        return False
    ext = os.path.join(CONFDIR, "leaf.ext")
    with open(ext, "w") as fh:
        fh.write("subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n"
                 "extendedKeyUsage=serverAuth\n" % HOST)
    csr = os.path.join(CONFDIR, "leaf.csr")
    r = run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
             "-keyout", LEAF_KEY, "-subj", "/CN=" + HOST, "-out", csr])
    if r.returncode != 0:
        print(r.stderr.decode()[:400], file=sys.stderr)
        return False
    r = run(["openssl", "x509", "-req", "-in", csr, "-CA", CA_PEM, "-CAkey", CA_PEM,
             "-CAcreateserial", "-out", LEAF_CRT, "-days", "365",
             "-extfile", ext])
    if r.returncode != 0:
        print(r.stderr.decode()[:400], file=sys.stderr)
        return False
    os.chmod(LEAF_KEY, 0o600)
    for f in (csr, ext):
        try:
            os.unlink(f)
        except OSError:
            pass
    return True


class Check(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "udt-check"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _cors(self):
        # The portal page lives on plain HTTP at another origin, so its fetch()
        # needs CORS to READ this response. A TLS failure rejects earlier and is
        # exactly the negative signal we want.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()
        self.close_connection = True

    def do_GET(self):
        # Reaching this handler at all means the TLS handshake completed, which
        # means this client trusts the CA. Record it: the portal will only
        # enable interception for an IP that appears here recently. The client
        # cannot fake this by simply POSTing "I installed it".
        try:
            with open(VERIFIED, "a") as fh:
                fh.write("%s %d\n" % (self.client_address[0], int(time.time())))
        except OSError:
            pass
        body = b'{"ca":"trusted"}'
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True


def serve():
    if not ensure_ca():
        print("no CA available; check server not starting", file=sys.stderr)
        sys.exit(1)
    if not ensure_leaf():
        print("could not sign the check leaf certificate", file=sys.stderr)
        sys.exit(1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(LEAF_CRT, LEAF_KEY)
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer.allow_reuse_address = True
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Check)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check-server"
    if cmd == "ensure-ca":
        sys.exit(0 if ensure_ca() and ensure_leaf() else 1)
    elif cmd == "ca-path":
        print(CA_CERT)
    else:
        serve()
