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


addons = [CertGate()]
