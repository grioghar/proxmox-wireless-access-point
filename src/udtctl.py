#!/usr/bin/env python3
"""upside-down-ternet :: operator CLI.

  udtctl who                       who has signed in, newest first
  udtctl trust <mac|email> [note]  give a device full speed, now and in future
  udtctl standard <mac|email>      mid tier
  udtctl guest <mac|email>         back to the trivial cap
  udtctl tiers                     show tier assignments
  udtctl kick <mac>                revoke authorization
  udtctl export [file.csv]         dump the consent ledger

  udtctl allow <mac>               lab mode: let this device associate at all
  udtctl deny <mac>                lab mode: remove it
  udtctl allowed                   lab mode: list the allowlist

  udtctl mitm <mac|email> on|off   opt a device into TLS interception. Only has
                                   effect if that device has installed the CA;
                                   otherwise its HTTPS simply fails.
"""
import csv, os, sqlite3, subprocess, sys

DB_PATH = os.environ.get("UDT_DB", "/var/lib/udt/udt.db")
NETSH = os.environ.get("UDT_NETSH", "/opt/udt/udt-net.sh")
VALID = ("guest", "standard", "trusted")


def db():
    return sqlite3.connect(DB_PATH, timeout=10)


def resolve(c, ident):
    """Accept a MAC, an email, or a name fragment; return (mac, ip, label)."""
    if ident.count(":") == 5:
        r = c.execute("SELECT mac,ip,name FROM clients WHERE mac=? ORDER BY id DESC LIMIT 1",
                      (ident.lower(),)).fetchone()
        return r if r else (ident.lower(), None, "(never signed in)")
    r = c.execute("""SELECT mac,ip,name FROM clients
                     WHERE email=? OR name LIKE ? ORDER BY id DESC LIMIT 1""",
                  (ident, "%" + ident + "%")).fetchone()
    return r


def cmd_who(_):
    c = db()
    rows = c.execute("""SELECT ts,name,email,phone,mac,ip,hostname,vendor
                        FROM clients ORDER BY id DESC LIMIT 50""").fetchall()
    if not rows:
        print("nobody has signed in yet")
        return
    tiers = dict(c.execute("SELECT mac,tier FROM tiers").fetchall())
    print("%-19s %-18s %-26s %-17s %-9s %s" %
          ("WHEN", "NAME", "EMAIL", "MAC", "TIER", "DEVICE"))
    for ts, name, email, phone, mac, ip, host, vend in rows:
        print("%-19s %-18s %-26s %-17s %-9s %s" %
              (ts, (name or "")[:18], (email or "")[:26], mac or "",
               tiers.get(mac, "guest"), host or vend or ""))
    c.close()


def set_tier(ident, tier, note=None):
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS tiers(
        mac TEXT PRIMARY KEY, tier TEXT NOT NULL, note TEXT)""")
    r = resolve(c, ident)
    if not r:
        print("no client matches %r -- try 'udtctl who'" % ident, file=sys.stderr)
        sys.exit(1)
    mac, ip, label = r
    c.execute("INSERT INTO tiers(mac,tier,note) VALUES(?,?,?) "
              "ON CONFLICT(mac) DO UPDATE SET tier=excluded.tier, note=excluded.note",
              (mac, tier, note))
    c.commit(); c.close()
    if ip:
        subprocess.run([NETSH, "tier", ip, tier], capture_output=True)
        print("%s (%s) -> %s, applied to %s now" % (label or mac, mac, tier, ip))
    else:
        print("%s -> %s, applied on next sign-in" % (mac, tier))


def cmd_tiers(_):
    c = db()
    try:
        rows = c.execute("SELECT mac,tier,note FROM tiers ORDER BY tier").fetchall()
    except sqlite3.OperationalError:
        rows = []
    if not rows:
        print("no tier overrides -- everyone is a guest")
    for mac, tier, note in rows:
        print("%-17s %-9s %s" % (mac, tier, note or ""))
    c.close()


def cmd_kick(args):
    if not args:
        print("usage: udtctl kick <mac>", file=sys.stderr); sys.exit(1)
    subprocess.run([NETSH, "deauthorize", args[0]], capture_output=True)
    print("revoked %s" % args[0])


ALLOWED = os.environ.get("UDT_ALLOWED", "/etc/udt/allowed_macs")


def _reload_hostapd():
    if subprocess.run(["hostapd_cli", "-p", "/var/run/hostapd", "reload"],
                      capture_output=True).returncode == 0:
        return True
    return subprocess.run(["pkill", "-HUP", "-x", "hostapd"],
                          capture_output=True).returncode == 0


def cmd_allow(args):
    if not args:
        print("usage: udtctl allow <mac> [note]", file=sys.stderr); sys.exit(1)
    mac = args[0].lower()
    os.makedirs(os.path.dirname(ALLOWED), exist_ok=True)
    cur = []
    if os.path.exists(ALLOWED):
        cur = [l.strip() for l in open(ALLOWED) if l.strip()]
    if any(l.split()[0].lower() == mac for l in cur if l and not l.startswith("#")):
        print("%s is already allowed" % mac); return
    with open(ALLOWED, "a") as fh:
        fh.write("%s\n" % mac)
    print("allowed %s%s" % (mac, " -- reloaded hostapd" if _reload_hostapd() else
                            " (restart the service to apply)"))


def cmd_deny(args):
    if not args:
        print("usage: udtctl deny <mac>", file=sys.stderr); sys.exit(1)
    mac = args[0].lower()
    if not os.path.exists(ALLOWED):
        print("no allowlist yet"); return
    keep = [l for l in open(ALLOWED) if l.strip().split(" ")[0].lower() != mac]
    open(ALLOWED, "w").writelines(keep)
    subprocess.run([NETSH, "deauthorize", mac], capture_output=True)
    print("denied %s%s" % (mac, " -- reloaded hostapd" if _reload_hostapd() else ""))


def cmd_allowed(_):
    if not os.path.exists(ALLOWED):
        print("no allowlist (lab mode not in use, or nothing added yet)"); return
    n = 0
    for line in open(ALLOWED):
        if line.strip() and not line.startswith("#"):
            print("  " + line.strip()); n += 1
    print("%d device(s) may associate" % n)


def cmd_mitm(args):
    if len(args) < 2 or args[1] not in ("on", "off"):
        print("usage: udtctl mitm <mac|email> on|off", file=sys.stderr); sys.exit(1)
    c = db()
    r = resolve(c, args[0])
    c.close()
    if not r:
        print("no client matches %r" % args[0], file=sys.stderr); sys.exit(1)
    mac = r[0]
    if args[1] == "on":
        print("Note: this only takes effect if the device has actually installed")
        print("the CA. If it has not, its HTTPS will fail rather than be readable.")
    subprocess.run([NETSH, "mitm-" + args[1], mac], capture_output=True)
    print("interception %s for %s" % (args[1], mac))


def cmd_export(args):
    out = args[0] if args else "udt-consent-ledger.csv"
    c = db()
    rows = c.execute("SELECT * FROM clients ORDER BY id").fetchall()
    cols = [d[0] for d in c.execute("SELECT * FROM clients LIMIT 1").description]
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(cols); w.writerows(rows)
    c.close()
    print("wrote %d records to %s" % (len(rows), out))


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip()); sys.exit(0)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "who":
        cmd_who(args)
    elif cmd in VALID:
        if not args:
            print("usage: udtctl %s <mac|email|name>" % cmd, file=sys.stderr); sys.exit(1)
        set_tier(args[0], cmd, " ".join(args[1:]) or None)
    elif cmd == "trust":
        set_tier(args[0], "trusted", " ".join(args[1:]) or None)
    elif cmd == "tiers":
        cmd_tiers(args)
    elif cmd == "kick":
        cmd_kick(args)
    elif cmd == "allow":
        cmd_allow(args)
    elif cmd == "deny":
        cmd_deny(args)
    elif cmd == "allowed":
        cmd_allowed(args)
    elif cmd == "mitm":
        cmd_mitm(args)
    elif cmd == "export":
        cmd_export(args)
    else:
        print(__doc__.strip()); sys.exit(1)


if __name__ == "__main__":
    main()
