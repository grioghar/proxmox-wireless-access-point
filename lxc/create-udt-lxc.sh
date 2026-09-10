#!/bin/bash
# upside-down-ternet :: create a Proxmox LXC that owns the wireless radio.
#
# Run this ON THE PROXMOX HOST. It creates a privileged container, hands the
# wireless PHY to that container's network namespace, and installs the stack
# inside it.
#
# Why privileged: hostapd, iptables, and tc all need real CAP_NET_ADMIN in the
# container's own netns. An unprivileged CT cannot do this. If that trade is
# unacceptable, run the stack directly on the node instead (../install.sh).
#
# Why LXC at all: Proxmox runs LXC natively, so this avoids installing Docker on
# a hypervisor -- something the Proxmox project explicitly discourages.
set -eu

CTID="${CTID:-}"
HOSTNAME_="${HOSTNAME_:-upside-down-ternet}"
BRIDGE="${BRIDGE:-vmbr0}"
STORAGE="${STORAGE:-local-lvm}"
TEMPLATE_STORE="${TEMPLATE_STORE:-local}"
# Set TMPL_VOLID to pin an exact template, e.g.
#   TMPL_VOLID=local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst
TMPL_VOLID="${TMPL_VOLID:-}"
DISK="${DISK:-4}"
MEMORY="${MEMORY:-512}"
PHY="${PHY:-}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

die() { echo "FATAL: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root on the Proxmox host"
command -v pct >/dev/null || die "pct not found -- this must run on a Proxmox node"

# ---- pick the radio ---------------------------------------------------------
if [ -z "$PHY" ]; then
  PHY="$(iw dev 2>/dev/null | awk '/phy#/{gsub("#","");print $1; exit}')"
  [ -z "$PHY" ] && PHY="$(ls /sys/class/ieee80211/ 2>/dev/null | head -1)"
fi
[ -n "$PHY" ] || die "no wireless phy found on this host"
echo "==> radio: $PHY"
iw phy "$PHY" info | sed -n '/Supported interface modes/,/^\t[a-zA-Z]/p' | grep -qE '^\s+\* AP$' \
  || die "$PHY does not support AP mode; nothing downstream can fix that"

# ---- pick a CTID ------------------------------------------------------------
if [ -z "$CTID" ]; then
  CTID=$(pvesh get /cluster/nextid 2>/dev/null || echo 900)
fi
echo "==> container id: $CTID"
pct status "$CTID" >/dev/null 2>&1 && die "CT $CTID already exists; set CTID=<free id>"

# ---- template ---------------------------------------------------------------
# Prefer a template that is already downloaded; only reach for the network if
# the host has none.
[ -n "$TMPL_VOLID" ] || TMPL_VOLID=$(pveam list "$TEMPLATE_STORE" 2>/dev/null \
             | awk '/debian-1[0-9]-standard/{print $1}' | sort -r | head -1)
if [ -z "$TMPL_VOLID" ]; then
  TMPL=$(pveam available 2>/dev/null | awk '/debian-13-standard/{print $2}' | sort -r | head -1)
  [ -n "$TMPL" ] || TMPL=$(pveam available 2>/dev/null | awk '/debian-12-standard/{print $2}' | sort -r | head -1)
  [ -n "$TMPL" ] || die "no Debian template available locally or upstream; run: pveam update"
  echo "==> downloading template $TMPL"
  pveam download "$TEMPLATE_STORE" "$TMPL"
  TMPL_VOLID="${TEMPLATE_STORE}:vztmpl/${TMPL}"
fi
echo "==> template: $TMPL_VOLID"

echo "==> creating privileged CT $CTID"
pct create "$CTID" "$TMPL_VOLID" \
  --hostname "$HOSTNAME_" --cores 2 --memory "$MEMORY" --swap 256 \
  --rootfs "${STORAGE}:${DISK}" --unprivileged 0 --onboot 1 \
  --net0 "name=eth0,bridge=${BRIDGE},ip=dhcp" \
  --description "upside-down-ternet captive portal AP (owns $PHY)"

CONF="/etc/pve/lxc/${CTID}.conf"
{
  echo "lxc.apparmor.profile: unconfined"
  echo "lxc.cap.drop:"
} >> "$CONF"

# Modules must be present in the HOST kernel; a container cannot modprobe.
echo "==> loading kernel modules on the host"
for m in sch_htb sch_sfq cls_u32 act_police iptable_nat iptable_mangle iptable_filter \
         xt_mark xt_mac xt_multiport xt_string xt_LOG xt_REDIRECT nf_conntrack; do
  modprobe "$m" 2>/dev/null || true
done
printf '%s\n' sch_htb sch_sfq cls_u32 act_police iptable_nat iptable_mangle \
  xt_mark xt_mac xt_multiport xt_string xt_LOG nf_conntrack \
  > /etc/modules-load.d/upside-down-ternet.conf

echo "==> starting CT"
pct start "$CTID"
sleep 8

echo "==> handing $PHY to the container"
"$(dirname "$0")/udt-phy-handoff.sh" "$CTID" "$PHY"

echo "==> installing the stack inside the CT"
pct exec "$CTID" -- mkdir -p /opt/udt-src
tar -C "$REPO" -cf - src templates install.sh wizard.sh udt.conf.example \
  | pct exec "$CTID" -- tar -C /opt/udt-src -xf -
pct exec "$CTID" -- chmod +x /opt/udt-src/install.sh /opt/udt-src/wizard.sh
# Do not let a failed install pass silently -- that is how a container gets
# built that nothing was ever installed into.
if ! pct exec "$CTID" -- bash -lc "cd /opt/udt-src && ./install.sh"; then
  echo "!! the in-container installer FAILED. CT $CTID exists but is not provisioned." >&2
  echo "   re-run it with: pct exec $CTID -- bash -lc 'cd /opt/udt-src && ./install.sh'" >&2
fi

# Re-apply the handoff on every host boot, before the CT's service needs it.
# The phy is deliberately NOT passed: phy numbering is not stable across a
# driver reload (a `modprobe -r iwlwifi` renumbers phy0 to phy1), and a unit
# pinned to the old name silently hands off nothing. The script auto-detects.
cat > /etc/systemd/system/udt-phy-handoff.service <<UNIT
[Unit]
Description=Hand the wireless PHY to LXC $CTID (upside-down-ternet)
After=pve-guests.service
Wants=pve-guests.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$(cd "$(dirname "$0")" && pwd)/udt-phy-handoff.sh $CTID

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable udt-phy-handoff.service >/dev/null 2>&1 || true

cat <<EOM

==> Container $CTID created and the radio is inside it.

Finish setup:
    pct enter $CTID
    cd /opt/udt-src && ./wizard.sh && ./install.sh
    systemctl enable --now upside-down-ternet

Watch it:
    pct exec $CTID -- journalctl -u upside-down-ternet -f

Note: while the CT holds $PHY, the Proxmox host cannot see or use that radio.
Stopping the CT returns it to the host.
EOM
