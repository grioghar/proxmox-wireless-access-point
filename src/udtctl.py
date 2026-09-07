#!/usr/bin/env python3
"""upside-down-ternet :: operator CLI.

  udtctl who                       who has signed in, newest first
  udtctl trust <mac|email> [note]  give a device full speed, now and in future
  udtctl standard <mac|email>      mid tier
  udtctl guest <mac|email>         back to the trivial cap
  udtctl tiers                     show tier assignments
  udtctl kick <mac>                revoke authorization
  udtctl export [file.csv]         dump the consent ledger
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
    elif cmd == "export":
        cmd_export(args)
    else:
        print(__doc__.strip()); sys.exit(1)


if __name__ == "__main__":
    main()
