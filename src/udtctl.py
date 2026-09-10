#!/usr/bin/env python3
"""upside-down-ternet :: operator CLI.

  udtctl who                       who has signed in, newest first
  udtctl trust <mac|email> [note]  give a device full speed, now and in future
  udtctl standard <mac|email>      mid tier
  udtctl guest <mac|email>         back to the trivial cap
  udtctl tiers                     show tier assignments
  udtctl kick <mac>                revoke authorization
  udtctl export [file.csv]         dump the consent ledger

  udtctl config                    show the running configuration
  udtctl config keys               list every tunable and what it does
  udtctl config set <KEY> <VALUE>  change one, with validation
  udtctl config get <KEY>

  udtctl allow <mac>               lab mode: let this device associate at all
  udtctl deny <mac>                lab mode: remove it
  udtctl allowed                   lab mode: list the allowlist

  udtctl mitm <mac|email> on|off   opt a device into TLS interception. Only has
                                   effect if that device has installed the CA;
                                   otherwise its HTTPS simply fails.
"""
import csv, os, re, sqlite3, subprocess, sys

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
    try:
        rows = c.execute("""SELECT ts,name,email,phone,mac,ip,hostname,vendor,
                            COALESCE(plex_signup,0) FROM clients
                            ORDER BY id DESC LIMIT 50""").fetchall()
    except sqlite3.OperationalError:
        rows = [r + (0,) for r in c.execute("""SELECT ts,name,email,phone,mac,ip,
                     hostname,vendor FROM clients ORDER BY id DESC LIMIT 50""")]
    if not rows:
        print("nobody has signed in yet")
        return
    tiers = dict(c.execute("SELECT mac,tier FROM tiers").fetchall())
    print("%-19s %-18s %-26s %-17s %-9s %-6s %s" %
          ("WHEN", "NAME", "EMAIL", "MAC", "TIER", "SIGNUP", "DEVICE"))
    for ts, name, email, phone, mac, ip, host, vend, signup in rows:
        print("%-19s %-18s %-26s %-17s %-9s %-6s %s" %
              (ts, (name or "")[:18], (email or "")[:26], mac or "",
               tiers.get(mac, "guest"), "YES" if signup else "-",
               host or vend or ""))
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
CONF = os.environ.get("UDT_CONF", "/etc/udt/udt.conf")
SERVICE = os.environ.get("UDT_SERVICE", "upside-down-ternet")

# key -> (validator, needs_restart, description)
BOOL = ("0", "1")


def _int(lo, hi):
    def f(v):
        return v.isdigit() and lo <= int(v) <= hi
    return f


def _rate(v):
    return bool(re.match(r"^\d+(kbit|mbit|gbit|bit)$", v, re.I))


def _ip(v):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v))


CONFIG_KEYS = {
    "UDT_SSID":            (lambda v: 0 < len(v) <= 32, True,  "network name"),
    "UDT_CHANNEL":         (_int(1, 196),               True,  "radio channel"),
    "UDT_HW_MODE":         (lambda v: v in ("g", "a"),  True,  "g=2.4GHz a=5GHz"),
    "UDT_COUNTRY":         (lambda v: len(v) == 2,      True,  "regulatory country"),
    "UDT_PASSPHRASE":      (lambda v: v == "" or 8 <= len(v) <= 63, True,
                            "WPA2 passphrase; blank = open"),
    "UDT_MODE":            (lambda v: v in ("public", "lab"), True,
                            "public=open portal, lab=WPA2+allowlist"),
    "UDT_TXPOWER":         (lambda v: v == "" or v.isdigit(), True,
                            "mBm, e.g. 800 = 8dBm; blank = max"),
    "UDT_RATE":            (_rate, False, "guest cap"),
    "UDT_RATE_STANDARD":   (_rate, False, "standard tier cap"),
    "UDT_RATE_TRUSTED":    (_rate, False, "trusted tier cap"),
    "UDT_FLIP":            (lambda v: v in BOOL, True,  "flip images on HTTP"),
    "UDT_MIN_RATE":        (lambda v: v in ("any", "g", "ofdm", "n", "ht", "ac", "vht"),
                            True, "minimum client: any|g|n|ac (refuses slower devices)"),
    "UDT_SIGNUP_URL":      (lambda v: v == "" or v.startswith(("http://", "https://")),
                            True, "mirror this signup page on the portal; blank = off"),
    "UDT_SIGNUP_LABEL":    (lambda v: True, True, "what to call that service on the portal"),
    "UDT_RETENTION_DAYS":  (_int(0, 3650), False, "consent record retention"),
    "UDT_MITM":            (lambda v: v in BOOL, True,  "enable TLS interception"),
    "UDT_MITM_AUTO":       (lambda v: v in BOOL, True,
                            "auto-promote devices that trust the CA"),
    "UDT_MITM_PORT":       (_int(1, 65535), True, "mitmproxy transparent port"),
    "UDT_MITM_CHECK_PORT": (_int(1, 65535), True, "cert-check HTTPS port"),
    "UDT_MITM_CHECK_HOST": (lambda v: bool(v), True, "cert-check hostname"),
    "UDT_MONITOR":         (lambda v: v in BOOL, True,  "enable operator dashboard"),
    "UDT_MONITOR_PORT":    (_int(1, 65535), True, "dashboard port"),
    "UDT_MONITOR_BIND":    (lambda v: v == "" or (_ip(v) and v != "0.0.0.0"), True,
                            "dashboard bind IP; blank = uplink. 0.0.0.0 refused"),
    "UDT_MONITOR_HOSTNAME": (lambda v: True, True,
                             "hostname the dashboard cert is issued for"),
    "UDT_MONITOR_TLS_CERT": (lambda v: v == "" or os.path.exists(v), True,
                             "PEM cert (fullchain) for the dashboard; blank = HTTP"),
    "UDT_MONITOR_TLS_KEY":  (lambda v: v == "" or os.path.exists(v), True,
                             "PEM private key for the dashboard"),
    "UDT_MONITOR_REDIRECT": (lambda v: v in BOOL, True,
                             "listen on plain HTTP and 301 to the HTTPS dashboard"),
    "UDT_MONITOR_REDIRECT_PORT": (_int(1, 65535), True,
                             "port for that redirect listener (usually 80)"),
    "UDT_DNS1":            (_ip, True, "upstream DNS"),
    "UDT_DNS2":            (_ip, True, "upstream DNS"),
    "UDT_RETENTION":       (_int(0, 3650), False, "(alias)"),
}
SECRET_KEYS = ("UDT_PASSPHRASE",)


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


def _conf_quote(value):
    """The inverse. Unquoted `UDT_SIGNUP_LABEL=my Plex server` makes the shell
    set the label to "my" and then try to run `Plex` as a command, so anything
    with whitespace or a shell metacharacter goes in double-quoted."""
    v = str(value)
    if v and not re.search(r"[^\w@%+=:,./-]", v):
        return v
    return '"' + re.sub(r'([$`"\\])', r"\\\1", v) + '"'


def _read_conf():
    out, order = {}, []
    if os.path.exists(CONF):
        for line in open(CONF):
            s = line.strip()
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                out[k.strip()] = _cfg_value(v)
                order.append(k.strip())
    return out, order


def _write_conf(key, value):
    lines = open(CONF).read().splitlines() if os.path.exists(CONF) else []
    done = False
    for i, line in enumerate(lines):
        if line.strip().startswith(key + "="):
            lines[i] = "%s=%s" % (key, _conf_quote(value))
            done = True
            break
    if not done:
        lines.append("%s=%s" % (key, _conf_quote(value)))
    tmp = CONF + ".tmp"
    with open(tmp, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONF)


def cmd_config(args):
    cur, _ = _read_conf()
    if not args or args[0] == "show":
        for k in sorted(cur):
            v = "<set, %d chars>" % len(cur[k]) if k in SECRET_KEYS and cur[k] else cur[k]
            desc = CONFIG_KEYS.get(k, (None, None, ""))[2]
            print("  %-22s %-22s %s" % (k, v, desc))
        return
    if args[0] == "keys":
        for k in sorted(CONFIG_KEYS):
            print("  %-22s %s" % (k, CONFIG_KEYS[k][2]))
        return
    if args[0] == "get":
        if len(args) < 2:
            print("usage: udtctl config get <KEY>", file=sys.stderr); sys.exit(1)
        print(cur.get(args[1], ""))
        return
    if args[0] != "set" or len(args) < 2:
        print("usage: udtctl config [show|keys|get <KEY>|set <KEY> <VALUE>]",
              file=sys.stderr)
        sys.exit(1)

    key = args[1]
    value = " ".join(args[2:]) if len(args) > 2 else ""
    if key not in CONFIG_KEYS:
        print("unknown key %r -- try 'udtctl config keys'" % key, file=sys.stderr)
        sys.exit(1)
    check, restart, _desc = CONFIG_KEYS[key]
    if not check(value):
        print("invalid value for %s: %r" % (key, value), file=sys.stderr)
        if key == "UDT_MONITOR_BIND":
            print("  refusing 0.0.0.0: that would expose the dashboard, which shows",
                  file=sys.stderr)
            print("  names and browsing history, to devices on the AP itself.",
                  file=sys.stderr)
        sys.exit(1)
    # cross-field rule: a private lab must not be an open network
    if key == "UDT_MODE" and value == "lab" and not cur.get("UDT_PASSPHRASE"):
        print("refusing: UDT_MODE=lab needs UDT_PASSPHRASE set first.", file=sys.stderr)
        sys.exit(1)
    if key == "UDT_PASSPHRASE" and value == "" and cur.get("UDT_MODE") == "lab":
        print("refusing: cannot clear the passphrase while UDT_MODE=lab.",
              file=sys.stderr)
        sys.exit(1)

    _write_conf(key, value)
    shown = "<set>" if key in SECRET_KEYS and value else (value or "<blank>")
    print("%s = %s" % (key, shown))

    if not restart:
        # tier caps are applied by re-running the shaper, no downtime needed
        subprocess.run([NETSH, "shape"], capture_output=True)
        print("applied live (no restart needed)")
    else:
        print("restart to apply:  systemctl restart %s" % SERVICE)


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
    elif cmd == "config":
        cmd_config(args)
    elif cmd == "export":
        cmd_export(args)
    else:
        print(__doc__.strip()); sys.exit(1)


if __name__ == "__main__":
    main()
