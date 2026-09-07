# upside-down-ternet

A self-contained captive-portal access point that demonstrates, to the person
using it, exactly how much a stranger's open Wi-Fi can learn about them — then
flips every image on the cleartext web upside down, because the
[original joke](https://www.ex-parrot.com/pete/upside-down-ternet.html) deserves
a modern implementation.

Built for Proxmox. Runs as a Docker container, a native LXC, or directly on a
node. Bring a wireless card that supports AP mode; the wizard checks that for you.

```
┌──────────┐   802.11    ┌───────────────────────────────────────────┐
│  client  │ ──────────► │ hostapd (ap_isolate)                      │
└──────────┘             │   ↓                                       │
                         │ dnsmasq  DHCP + DNS + RFC8910 portal URI  │
   unauthorized ────────►│ portal.py   consent gate, fingerprinting  │
                         │   ↓ MAC marked in iptables                │
   authorized ──────────►│ squid    logs URLs (HTTP) and SNI (HTTPS) │
                         │   ↓ HTTP only                             │
                         │ flipproxy.py   rotates images 180°        │
                         │   ↓                                       │
                         │ NAT ──► uplink                            │
                         └───────────────────────────────────────────┘
```

## What it does

- **Captive portal.** Every client is denied egress until it submits a name,
  email, phone number and an explicit consent checkbox. The page greets visitors
  using the device hostname their phone volunteers over DHCP (`Steve's-iPhone`),
  and shows them their MAC, vendor, OS, browser, language, GPU, screen and
  timezone — all collected before they typed anything. That is the lesson.
- **Consent ledger.** Every sign-in is recorded in SQLite with a timestamp and
  device fingerprint, exportable to CSV.
- **Activity logging.** Squid records full URLs for cleartext HTTP and the SNI
  hostname for HTTPS. Nothing is decrypted.
- **Per-client bandwidth tiers.** `guest` (default, trivial), `standard`, and
  `trusted` (full speed), applied in both directions and settable per device.
- **Protocol restriction.** Authorized clients get TCP 80/443 and nothing else.
  That single rule is what stops BitTorrent, WireGuard, OpenVPN, IPsec and PPTP.
- **Client isolation.** `ap_isolate=1` at layer 2 plus an L3 drop rule, and the
  portal network is firewalled away from the host's real LAN.
- **Image flipping** on cleartext HTTP, via ImageMagick.

## Deploying

Run the wizard first, on the machine that has the radio. It detects the card,
proves it can do AP mode, finds a legal and uncongested channel, picks a
non-colliding subnet, and writes `udt.conf`.

```bash
sudo ./wizard.sh          # interactive setup
sudo ./wizard.sh --check  # diagnose only, write nothing
```

### Docker

```bash
docker compose up -d --build
docker compose logs -f
```

The container uses `network_mode: host` because it drives a physical radio and
rewrites the host firewall. **It must run on the machine with the wireless card**
— it cannot be pointed at a remote radio. Note that Proxmox discourages running
Docker on a node; if that matters to you, use LXC.

### LXC (recommended on Proxmox)

Run on the Proxmox host. This creates a privileged container, hands it the
wireless PHY, and installs the stack inside:

```bash
sudo lxc/create-udt-lxc.sh
pct enter <CTID>
cd /opt/udt-src && ./wizard.sh && ./install.sh
systemctl enable --now upside-down-ternet
```

A wireless PHY belongs to exactly one network namespace at a time, so while the
container holds it the host cannot use that radio. Stopping the container gives
it back. The container must be **privileged** — `hostapd`, `iptables` and `tc`
need real `CAP_NET_ADMIN` in their own namespace.

### Bare metal

```bash
sudo ./install.sh
sudo systemctl enable --now upside-down-ternet
```

## Operating it

```bash
udtctl who                     # who signed in, with tier
udtctl trust alice@example.com # full speed, now and on every future sign-in
udtctl standard aa:bb:cc:dd:ee:ff
udtctl guest  aa:bb:cc:dd:ee:ff
udtctl kick   aa:bb:cc:dd:ee:ff
udtctl export ledger.csv
```

Under Docker, prefix with
`docker exec -it upside-down-ternet python3 /opt/udt/udtctl.py`.

## Limits — read these

**Only cleartext HTTP is inspected or modified.** HTTPS is peeked for its SNI
hostname and spliced through untouched. There is no CA, no certificate
generation, and no ability to read message bodies.

**This project will not implement TLS interception or HTTPS→HTTP downgrade.**
Both were considered and deliberately rejected. Stripping TLS pushes other
people's passwords and session cookies over the air in cleartext, where anyone
in radio range can collect them — a consent checkbox covers monitoring by the
operator, not exposure to the whole neighbourhood. It also does not work:
HSTS preloading means browsers refuse plain HTTP for essentially every site
worth attacking, so the practical result is a portal where half the web appears
broken. Logging SNI plus a "here is what we already know about you" page teaches
the same lesson and is safe to hand a stranger.

**VPN blocking is port- and protocol-based**, so it catches WireGuard (51820),
OpenVPN (1194), IPsec (500/4500, ESP, AH), L2TP and PPTP. It cannot catch a VPN
deliberately tunnelled over TCP 443 — that is indistinguishable from HTTPS
without decryption, which is out of scope by the rule above. The same applies to
DNS-over-HTTPS.

**BitTorrent blocking** is the default-deny rule plus a payload string match.
Encrypted peer connections on port 443 are not detected.

**You are collecting personal data.** Names, emails, phone numbers, MAC
addresses and browsing metadata. `UDT_RETENTION_DAYS` prunes it (default 30).
Recording other people's network activity is regulated differently in different
places, and the consent checkbox is what makes this defensible — do not remove
it, and check your local rules before running this anywhere public.

## The regulatory trap

If `hostapd` refuses to start on 5 GHz, it is almost never the card. Many
adapters — Intel's AX2xx series especially — are **self-managed** regulatory
devices: `iw reg set US` changes the global domain but not the card's own, and
the card's is what governs. A card reporting `country 00` marks every 5 GHz
channel `no IR` (transmission forbidden), and some grant 5 GHz only while
*concurrently associated to another AP* (`IR-CONCURRENT`), which is useless for
a standalone AP.

Two things to check, both of which `wizard.sh --check` reports:

1. `wireless-regdb` installed on the **host** — without it the kernel logs
   `cfg80211: failed to load regulatory.db` and ignores every regulatory hint.
2. `iw phy phy0 reg get` — if it says `country 00`, 5 GHz is not happening.
   Use 2.4 GHz, which is unrestricted under the world domain.

Also note `iw phy info` may show a channel as available while the kernel still
refuses to beacon on it. Trust hostapd's error, not `iw`.

## Testing

```bash
docker run --rm -v $PWD/udt.conf:/etc/udt/udt.conf:ro \
  -v $PWD/tests/smoke.sh:/opt/udt/smoke.sh:ro \
  --entrypoint bash upside-down-ternet:latest /opt/udt/smoke.sh
```

Covers config rendering, portal serving and validation, the image flipper, and
the RFC1918 guard. Does not cover anything requiring a radio.

## License

MIT. See `LICENSE`.
