"""upside-down-ternet :: mitmproxy addon -- the safety net.

Only devices already marked as trusting the CA are routed here by iptables, so
in the normal case this addon does nothing. It exists for the case where that
belief goes stale: someone deletes the certificate, or restores their phone, and
suddenly every HTTPS request they make would break.

When a client-side TLS handshake fails, that is the device telling us it does not
trust our CA. We immediately demote it back to the spliced guest path, so the
worst case is one failed connection rather than a device with no working internet.
"""
import subprocess, time

NETSH = "/opt/udt/udt-net.sh"
REQLOG = "/var/lib/udt/mitm-requests.log"
DEBOUNCE = 30.0          # seconds between demotions for the same client
_last = {}

try:
    from mitmproxy import ctx

    def _log(msg):
        try:
            ctx.log.warn(msg)
        except Exception:
            print(msg, flush=True)
except Exception:                                     # pragma: no cover
    def _log(msg):
        print(msg, flush=True)


def _peer(data):
    for path in (lambda d: d.context.client.peername[0],
                 lambda d: d.client_conn.peername[0]):
        try:
            return path(data)
        except Exception:
            continue
    return None


class CertGate:
    def tls_failed_client(self, data):
        ip = _peer(data)
        if not ip:
            return
        now = time.time()
        if now - _last.get(ip, 0) < DEBOUNCE:
            return
        _last[ip] = now
        _log("udt: client %s rejected our certificate -- demoting to guest" % ip)
        try:
            subprocess.run([NETSH, "demote", ip], capture_output=True, timeout=15)
        except Exception as e:
            _log("udt: demote failed for %s: %s" % (ip, e))

    def tls_established_client(self, data):
        ip = _peer(data)
        if ip:
            _last.pop(ip, None)

    # Squid never sees an intercepted client's traffic, so the operator log for
    # those devices has to come from here. One tab-separated line per response,
    # same shape the monitor parses out of squid's access.log.
    def response(self, flow):
        try:
            r, req = flow.response, flow.request
            ip = flow.client_conn.peername[0]
            line = "%.3f\t%s\t%s\t%s\t%d\t%d\tmitm\n" % (
                time.time(), ip, req.method,
                req.pretty_url[:400], r.status_code,
                len(r.raw_content or b""))
            with open(REQLOG, "a") as fh:
                fh.write(line)
        except Exception:
            pass

    def error(self, flow):
        try:
            ip = flow.client_conn.peername[0]
            url = flow.request.pretty_url[:400] if flow.request else "-"
            with open(REQLOG, "a") as fh:
                fh.write("%.3f\t%s\t%s\t%s\t0\t0\tmitm-error\n" %
                         (time.time(), ip, "ERR", url))
        except Exception:
            pass


addons = [CertGate()]
