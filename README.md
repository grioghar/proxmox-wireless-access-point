# proxmox-wireless-access-point

Turn a Proxmox node's wireless card into a real access point — captive portal,
per-device bandwidth tiers, protocol filtering, request logging and a live
operator dashboard — running in an unprivileged-adjacent LXC, a Docker
container, or straight on the host.

It also flips every image on the cleartext web upside down, because it grew out
of [Upside-Down-Ternet](https://www.ex-parrot.com/pete/upside-down-ternet.html)
and that part earned its keep.

```
┌──────────┐   802.11    ┌───────────────────────────────────────────────┐
│  client  │ ──────────► │ hostapd (ap_isolate)                          │
└──────────┘             │   ↓                                           │
                         │ dnsmasq   DHCP + DNS + RFC8910 portal hint    │
   unauthorised ────────►│ portal    consent gate + device fingerprint   │
                         │   ↓  MAC marked in iptables                   │
   guest ───────────────►│ squid → flipproxy   logged, throttled, flipped│
   trusted (opt-in CA) ─►│ mitmproxy           logged, full speed        │
                         │   ↓                                           │
                         │ NAT ──► uplink                                │
                         └───────────────────────────────────────────────┘
                                   dashboard :8090 (uplink side only)
```

---

## 1. Will your hardware work?

**The card must support AP mode.** Most Intel, Atheros and MediaTek cards do;
many cheap USB dongles do not. Check before anything else:

```bash
iw list | grep -A10 "Supported interface modes"
```

You need `* AP` in that list. If it is absent, no amount of configuration will
help — pick another card.

Then let the wizard check everything else for you, changing nothing:

```bash
sudo ./wizard.sh --check
```

It reports the interface, AP-mode support, regulatory state, which channels are
legally usable, neighbour congestion, and — critically — it **starts hostapd on
the candidate channel to confirm it actually works** rather than trusting what
`iw` advertises.

### The 5 GHz trap (read this before filing a bug)

If 5 GHz refuses to start, it is almost never a broken card:

- Many cards (Intel AX200/AX210 especially) are **self-managed** regulatory
  devices. `iw reg set US` changes the *global* domain but not the card's own,
  and the card's is what governs.
- A card reporting `country 00` marks every 5 GHz channel `no IR` — transmission
  forbidden. Some grant 5 GHz only while *concurrently associated to another AP*
  (`IR-CONCURRENT`), which is useless for a standalone AP.
- `iw phy info` will happily list a channel as available that the kernel then
  refuses to beacon on. **Trust hostapd's error, not `iw`.**

Two things to verify:

```bash
ls /lib/firmware/regulatory.db     # missing => kernel ignores all regulatory hints
iw phy phy0 reg get                # 'country 00' => 5 GHz is not happening
```

Install `wireless-regdb` **on the host** if it is absent. If the card still
reports `country 00`, use 2.4 GHz — it is unrestricted under the world domain.
The wizard detects all of this and falls back on its own.

---

## 2. Deploying in LXC (recommended on Proxmox)

Proxmox runs LXC natively and [discourages Docker on the node
itself](https://pve.proxmox.com/wiki/Linux_Container), so this is the path to
prefer. One command, run **on the Proxmox host**:

```bash
git clone https://github.com/grioghar/proxmox-wireless-access-point.git
cd proxmox-wireless-access-point
sudo ./lxc/create-udt-lxc.sh
```

That will:

1. find the wireless PHY and refuse to continue if it cannot do AP mode
2. create a **privileged** container (Debian, 512 MB, 4 GB disk)
3. load the kernel modules the container cannot load itself, and persist them
4. hand the PHY into the container's network namespace
5. install the stack inside
6. register a host unit so the PHY is handed over again after every reboot

Then finish inside the container:

```bash
pct enter <CTID>
cd /opt/udt-src && ./wizard.sh && ./install.sh
systemctl enable --now upside-down-ternet
```

### Tunables

```bash
CTID=950 BRIDGE=vmbr0 STORAGE=local-lvm DISK=4 MEMORY=512 \
  sudo ./lxc/create-udt-lxc.sh
```

`PHY=phy1` selects a specific radio if the host has several.

### Things worth understanding

- **A wireless PHY belongs to exactly one network namespace at a time.** While
  the container holds it, the Proxmox host cannot see or use that radio.
  Stopping the container gives it back.
- **The container must be privileged.** `hostapd`, `iptables` and `tc` need real
  `CAP_NET_ADMIN` in their own namespace; an unprivileged CT cannot do this. If
  that trade is unacceptable, run `./install.sh` on the node instead.
- The script sets `lxc.apparmor.profile: unconfined` and clears `lxc.cap.drop`
  for the same reason.
- Kernel modules (`sch_htb`, `cls_u32`, `act_police`, the `xt_*` matches) must
  exist on the **host**; a container cannot `modprobe`. The script loads them and
  writes `/etc/modules-load.d/upside-down-ternet.conf`.

### Moving the radio by hand

```bash
sudo ./lxc/udt-phy-handoff.sh <CTID> [phy0]
```

Useful after a manual container restart, or to move the radio between guests.

---

## 3. Other deployment targets

### Docker

```bash
sudo ./wizard.sh
docker compose up -d --build
```

Uses `network_mode: host` because it drives a physical radio and rewrites the
host firewall, so **it must run on the machine holding the card** — it cannot be
pointed at a remote radio. On a Proxmox node prefer LXC.

Note that squid's intercept port (3128) collides with Proxmox's own
`spiceproxy` if you run this directly on a PVE host outside a container. In LXC
or Docker-with-its-own-netns this does not arise; on bare PVE, change
`UDT_MONITOR_PORT`/squid ports or use a container.

### Bare metal (any Debian-family host)

```bash
sudo ./wizard.sh
sudo ./install.sh
sudo systemctl enable --now upside-down-ternet
```

---

## 4. What each piece does

| Component | Role |
|---|---|
| `hostapd` | the AP itself, with `ap_isolate=1` so stations cannot see each other |
| `dnsmasq` | DHCP + DNS, and the RFC 8910 hint that pops the sign-in sheet |
| `portal.py` | consent gate, device fingerprinting, CA install page |
| `squid` | logs URLs for HTTP and SNI hostnames for HTTPS, without decrypting |
| `flipproxy.py` | rotates images 180° on cleartext HTTP |
| `mitmproxy` | optional, opt-in, cert-gated full interception |
| `monitor.py` | live operator dashboard, uplink-side only |
| `udt-net.sh` | firewall, NAT, classification marks, HTB/policer shaping |
| `udtctl` | operator CLI |

### Client classification

Every device starts unauthorised and can reach only DNS and the portal. After
that:

| state | egress | bandwidth | HTTPS |
|---|---|---|---|
| unauthorised | portal only | — | blocked |
| guest | TCP 80/443 only | `UDT_RATE` (128 kbit) | spliced, SNI logged |
| standard | TCP 80/443 only | `UDT_RATE_STANDARD` | spliced, SNI logged |
| trusted | TCP 80/443 only | `UDT_RATE_TRUSTED` | intercepted, if CA installed |

Because authorised clients get **TCP 80/443 and nothing else**, BitTorrent,
WireGuard, OpenVPN, IPsec and PPTP all die at the default-deny rule.

---

## 5. Operating it

```bash
udtctl who                        # who signed in, with tier
udtctl trust alice@example.com    # full speed, now and on every future sign-in
udtctl guest  aa:bb:cc:dd:ee:ff
udtctl kick   aa:bb:cc:dd:ee:ff
udtctl export ledger.csv

udtctl allow  aa:bb:cc:dd:ee:ff   # lab mode: may this device associate at all
udtctl mitm   aa:bb:cc:dd:ee:ff on
```

Under Docker, prefix with
`docker exec -it upside-down-ternet python3 /opt/udt/udtctl.py`.
In LXC, `pct exec <CTID> -- udtctl …`.

### The dashboard

`http://<uplink-ip>:8090/` — associated stations with signal, live throughput,
classification and cap, plus a scrolling request tail filterable per client.
Refresh interval is selectable from 1 s to 60 s (or off) and remembered per
browser.

The tail merges two sources, because they are mutually exclusive: squid logs
guests, the mitmproxy addon logs intercepted devices. Each row is labelled with
its origin.

**It binds to the uplink address only, never `0.0.0.0`**, and the firewall drops
AP-side traffic aimed at its port. The page shows names, emails, phone numbers
and browsing history; a guest must never be able to load it. `udtctl config`
refuses `UDT_MONITOR_BIND=0.0.0.0` for that reason.

---

## 6. Configuration

Everything the wizard asks is editable afterwards, with validation:

```bash
udtctl config                        # what is running now
udtctl config keys                   # every tunable and what it does
udtctl config set UDT_RATE 512kbit   # shaping changes apply live
udtctl config set UDT_MITM_AUTO 1    # tells you when a restart is needed
```

Invalid values and unsafe combinations are refused — `UDT_MODE=lab` without a
passphrase, a dashboard bound to every interface, a malformed `tc` rate.

| key | meaning |
|---|---|
| `UDT_IFACE` `UDT_SSID` `UDT_CHANNEL` `UDT_HW_MODE` | radio basics (`g`=2.4 GHz, `a`=5 GHz) |
| `UDT_COUNTRY` `UDT_TXPOWER` | regulatory domain; TX power in mBm (800 = 8 dBm) |
| `UDT_MODE` | `public` (open + portal) or `lab` (WPA2 + optional MAC allowlist) |
| `UDT_PASSPHRASE` | WPA2 passphrase; blank = open. Required for `lab` |
| `UDT_NET` `UDT_GW` `UDT_DHCP_START` `UDT_DHCP_END` `UDT_UPLINK` | addressing |
| `UDT_RATE` `UDT_RATE_STANDARD` `UDT_RATE_TRUSTED` | per-tier caps, both directions |
| `UDT_FLIP` | flip images on cleartext HTTP |
| `UDT_RETENTION_DAYS` | consent-ledger retention; 0 = forever |
| `UDT_MITM` `UDT_MITM_AUTO` | interception off by default; auto-sorting off by default |
| `UDT_MONITOR` `UDT_MONITOR_PORT` `UDT_MONITOR_BIND` | dashboard |

### Two postures

- **`public`** — open network, captive portal is the gate. The teaching/demo AP.
- **`lab`** — WPA2 mandatory (it refuses to start open), plus an optional MAC
  allowlist. The allowlist is only enforced once it has an entry, because
  enforcing an empty one locks you out with no way to discover your own MAC.

---

## 7. Optional TLS interception

Off by default. When enabled, a device is intercepted **only** if both hold:

1. it has been opted in, and
2. it genuinely trusts the CA, proven by a live TLS handshake

The proof is server-side. A hostname served by our own DNS presents a leaf
signed by the mitmproxy CA; reaching it requires a completed handshake, which
requires that CA to be installed and trusted on that device. Only successful
handshakes are recorded, so a client cannot self-assert "I installed it".

With `UDT_MITM_AUTO=1`, one radio serves two audiences at once. The portal page
probes that endpoint in the background:

- **no certificate** → spliced, throttled, images flipped, and it sees no error
- **certificate** → promoted to full speed and intercepted, with a banner saying so

The probe deliberately does **not** test on the client's real traffic. Routing
everyone through mitmproxy and watching who fails would work, but that failure
is a certificate warning in a stranger's browser — it trains people to click
through TLS errors and hard-fails every HSTS site.

If a trusted device later deletes the CA, the addon catches the handshake
failure and demotes it, so the cost is one failed connection rather than a
device with no working internet.

---

## 8. Limits, and two things this will not do

**Only cleartext HTTP is inspected or modified** unless interception is on.
HTTPS is peeked for its SNI hostname and spliced through untouched.

**This project will not implement HTTPS→HTTP downgrade (SSL stripping).**
Stripping TLS pushes other people's passwords and session cookies over the air
in cleartext, where anyone in radio range can collect them — a consent checkbox
covers monitoring by the operator, not exposure to the whole neighbourhood. It
also does not work: HSTS preloading means browsers refuse plain HTTP for
essentially every site worth attacking, so the practical result is a portal
where half the web appears broken.

**Browsers cannot report the OS username.** There is no such API, by design. The
portal greets people using the DHCP hostname their device volunteers
(`Steve's-iPhone`), plus MAC vendor, User-Agent, GPU string, screen and timezone.

**VPN blocking is port- and protocol-based.** It catches WireGuard (51820),
OpenVPN (1194), IPsec (500/4500, ESP, AH), L2TP and PPTP. It cannot catch a VPN
deliberately tunnelled over TCP 443 — indistinguishable from HTTPS without
decryption. Same for DNS-over-HTTPS.

**You are collecting personal data.** Names, emails, phone numbers, MACs and
browsing metadata. `UDT_RETENTION_DAYS` prunes it. Recording other people's
network activity is regulated differently in different places, and the consent
checkbox is what makes this defensible — do not remove it, and check your local
rules before running this anywhere public.

---

## 9. Troubleshooting

| symptom | cause |
|---|---|
| hostapd exits immediately | channel not permitted for AP mode; run `./wizard.sh --check` |
| 5 GHz refuses, 2.4 works | self-managed regulatory domain reporting `country 00` (§1) |
| `Squid is already running` | the distro squid unit auto-started; `systemctl disable --now squid` |
| `mimeLoadIcon: cannot parse internal URL` | squid needs one non-intercept port; the shipped config has one on loopback |
| flipping does nothing | ImageMagick 6 ships `convert`, 7 ships `magick`; the proxy detects either |
| dashboard unreachable | it binds to the uplink IP, not `0.0.0.0`, by design |
| no clients get addresses | another dnsmasq is bound to the interface |

```bash
journalctl -u upside-down-ternet -f          # everything
pct exec <CTID> -- iw dev                    # is the radio in the container?
pct exec <CTID> -- iw dev wlan0 station dump # who is associated
```

### Testing without a radio

```bash
docker run --rm -v $PWD/udt.conf:/etc/udt/udt.conf:ro \
  -v $PWD/tests/smoke.sh:/opt/udt/smoke.sh:ro \
  --entrypoint bash upside-down-ternet:latest /opt/udt/smoke.sh
```

Covers config rendering, the portal, validation, the image flipper and the
RFC1918 guard.

---

## License

MIT. See `LICENSE`.
