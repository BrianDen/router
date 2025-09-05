#!/usr/bin/env bash

# WAN: eno1
# LAN: enx00f001e00c2f
# IPTV: 5C:22:DA:07:0F:94
# HP Server: 10:E7:C6:00:F1:6D
# HP Router: 6C:02:E0:92:0D:82

# Usage
# sudo chmod +x setup_router.sh
# No VLAN on WAN:
# sudo WAN_IF=eno1 LAN_IF=enx00f001e00c2f ./setup_router.sh

# No VLAN on WAN with decoder:
# sudo WAN_IF=eno1 LAN_IF=enx00f001e00c2f DECODER_MAC=5C:22:DA:07:0F:94 ./setup_router.sh

# VLAN 20 on WAN:
# sudo WAN_IF=eno1 WAN_VLAN=20 LAN_IF=enx00f001e00c2f ./setup_router.sh

set -euo pipefail

### ====== USER SETTINGS =======================================================
: "${WAN_IF:?Set WAN_IF (e.g., enp1s0) before running}"
: "${LAN_IF:?Set LAN_IF (e.g., enp2s0) before running}"
WAN_VLAN="${WAN_VLAN:-}"  # e.g., 20 for WAN on VLAN 20; empty = no VLAN

# LAN DNS domain (don’t use .local; RFC 8375 recommends home.arpa)
LAN_DOMAIN="${LAN_DOMAIN:-home.arpa}"

LAN_NET="192.168.1.0/24"
LAN_GW="192.168.1.1"
LAN_DHCP_START="192.168.1.100"
LAN_DHCP_END="192.168.1.199"

DECODER_MAC="${DECODER_MAC:-}"             # optional, e.g. :11:22:33:44:55
DECODER_IP="${DECODER_IP:-192.168.1.10}"
IPTV_VENDOR_CLASS="${IPTV_VENDOR_CLASS:-IPTV}"  # matches IPTV*

# Derive the actual WAN device we’ll use
if [ -n "${WAN_VLAN}" ]; then
  WAN_DEV="${WAN_IF}.${WAN_VLAN}"
else
  WAN_DEV="${WAN_IF}"
fi

###############################################################################
echo "[*] Disabling conflicting services…"
systemctl disable --now systemd-networkd || true
systemctl disable --now systemd-resolved || true

echo "[*] Updating apt and installing packages…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  dnsmasq igmpproxy nftables isc-dhcp-client iproute2 ifupdown \
  vlan tcpdump jq unattended-upgrades

# Ensure VLAN kernel module loads
echo 8021q >/etc/modules-load.d/8021q.conf

echo "[*] Enable automatic security updates…"
unattended-upgrades

echo "[*] Enabling IP forwarding and kernel knobs…"
cat >/etc/sysctl.d/99-router.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1

# Reverse path filtering: disable globally + for new interfaces
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0

# NOTE: Per-interface settings for accept_ra and rp_filter are applied
# in /etc/network/interfaces via /proc (works even if iface name has a dot).
EOF
sysctl --system >/dev/null

echo "[*] Configuring network interfaces (ifupdown)… (backup at /etc/network/interfaces.bak)"
cp -a /etc/network/interfaces /etc/network/interfaces.bak || true
{
  cat <<'EOF'
# Loopback
auto lo
iface lo inet loopback
EOF

  if [ -n "${WAN_VLAN}" ]; then
    # Physical WAN kept manual; VLAN subif is the real WAN
    cat <<EOF
# === WAN (PHY) ===
allow-hotplug ${WAN_IF}
iface ${WAN_IF} inet manual

# === WAN (VLAN ${WAN_VLAN}) ===
allow-hotplug ${WAN_DEV}
iface ${WAN_DEV} inet dhcp
    vlan-raw-device ${WAN_IF}
    pre-up sh -c "echo 0 > /proc/sys/net/ipv4/conf/\$IFACE/rp_filter"
    post-up sh -c "echo 2 > /proc/sys/net/ipv6/conf/\$IFACE/accept_ra"

iface ${WAN_DEV} inet6 manual
EOF
  else
    cat <<EOF
# === WAN ===
allow-hotplug ${WAN_DEV}
iface ${WAN_DEV} inet dhcp
    pre-up sh -c "echo 0 > /proc/sys/net/ipv4/conf/\$IFACE/rp_filter"
    post-up sh -c "echo 2 > /proc/sys/net/ipv6/conf/\$IFACE/accept_ra"

iface ${WAN_DEV} inet6 manual
EOF
  fi

  cat <<EOF
# === LAN ===
allow-hotplug ${LAN_IF}
iface ${LAN_IF} inet static
    address ${LAN_GW}
    netmask 255.255.255.0
    pre-up sh -c "echo 0 > /proc/sys/net/ipv4/conf/\$IFACE/rp_filter"
EOF
} >/etc/network/interfaces

echo "[*] Requesting the exact DHCPv4 options required on WAN (Option 55)…"
cat >/etc/dhcp/dhclient.conf <<'EOF'
request subnet-mask, routers, domain-name-servers, host-name, domain-name,
        ntp-servers, vendor-encapsulated-options, dhcp-lease-time,
        dhcp-server-identifier, bootfile-name, classless-static-routes;
EOF

echo "[*] Configuring DHCPv6-PD client for WAN…"
cat >/etc/dhcp/dhclient6.conf <<EOF
interface "${WAN_DEV}" {
    request dhcp6.name-servers, dhcp6.domain-search;
}
EOF

echo "[*] Hook to copy WAN DHCP options to LAN DHCP (spoofing) + install IPv6 PD on LAN…"
mkdir -p /etc/dhcp/dhclient-exit-hooks.d
sudo tee /etc/dhcp/dhclient-exit-hooks.d/99-proximus-options >/dev/null <<'EOF'
#!/bin/sh
# POSIX-safe dhclient exit hook: copy WAN DHCP options to dnsmasq (decoder)
# and install IPv6 PD /64 on the chosen LAN interface.

# Interface to advertise PD/RA on (written by setup script)
LAN_IF_FILE="/etc/router-lan-if"
if [ -f "$LAN_IF_FILE" ]; then
  LAN_IF="$(cat "$LAN_IF_FILE")"
else
  LAN_IF=""
fi

OPTS_FILE="/etc/dnsmasq.d/iptv-wan-options.conf"
RESOLV_FILE="/run/dnsmasq-resolv.conf"

restart_dnsmasq() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart dnsmasq 2>/dev/null || true
  else
    service dnsmasq restart 2>/dev/null || true
  fi
}

# Only act on expected reasons
case "${reason:-}" in
  BOUND|RENEW|REBIND|REBOOT|EXPIRE|TIMEOUT|BOUND6|RENEW6|REBIND6|RELEASE6|STOP6) ;;
  *)  # be a no-op; don't exit the parent script
      return 0 2>/dev/null || :
      ;;
esac

# Build a fresh file every time to avoid duplicates
TMP="${OPTS_FILE}.tmp"
mkdir -p "$(dirname "$OPTS_FILE")"
: > "$TMP"
{
  echo "# Generated by dhclient hook at $(date)"
  echo "# Tag 'decoder' = vendor-class starts with 'IPTV'"
} >> "$TMP"

# ---------- IPv4 options to decoder ----------
if [ -n "${new_domain_name_servers:-}" ]; then
  : > "$RESOLV_FILE"
  for ip in $new_domain_name_servers; do
    echo "nameserver $ip" >> "$RESOLV_FILE"
  done
  DNS_CSV=$(printf '%s' "$new_domain_name_servers" | tr ' ' ',')
  echo "dhcp-option=tag:decoder,option:dns-server,$DNS_CSV" >> "$TMP"
fi

if [ -n "${new_ntp_servers:-}" ]; then
  NTP_CSV=$(printf '%s' "$new_ntp_servers" | tr ' ' ',')
  echo "dhcp-option=tag:decoder,option:ntp-server,$NTP_CSV" >> "$TMP"
fi

if [ -n "${new_bootfile_name:-}" ]; then
  printf 'dhcp-option=tag:decoder,option:bootfile-name,"%s"\n' "$new_bootfile_name" >> "$TMP"
fi

if [ -n "${new_vendor_encapsulated_options:-}" ]; then
  echo "dhcp-option=tag:decoder,43,$new_vendor_encapsulated_options" >> "$TMP"
fi

# Optional: pass ISP domain (Option 15) to decoder too
if [ -n "${new_domain_name:-}" ]; then
  echo "dhcp-option=tag:decoder,option:domain-name,$new_domain_name" >> "$TMP"
fi

# ---------- IPv6 PD: install a /64 on LAN_IF ----------
if [ -n "${new_ip6_prefix:-}" ] && [ -n "$LAN_IF" ]; then
  base="$new_ip6_prefix"
  case "$base" in
    *::) addr="${base}1/64" ;;
    *)   addr="${base}::1/64" ;;
  esac
  # remove existing /64s that match the delegated prefix only
  for cidr in $(ip -6 -o addr show dev "$LAN_IF" scope global | awk '{print $4}'); do
    case "$cidr" in
      ${new_ip6_prefix%::*}*/64) ip -6 addr del "$cidr" dev "$LAN_IF" 2>/dev/null || true ;;
    esac
  done
  ip -6 addr add "$addr" dev "$LAN_IF" 2>/dev/null || true
fi

# ---------- IPv6 DNS/search to LAN ----------
if [ -n "${new_dhcp6_name_servers:-}" ] || [ -n "${new_dhcp6_domain_search:-}" ]; then
  echo "# IPv6 options from WAN:" >> "$TMP"
  if [ -n "${new_dhcp6_name_servers:-}" ]; then
    DNS6_CSV=$(printf '%s' "$new_dhcp6_name_servers" | tr ' ' ',')
    echo "dhcp-option=option6:dns-server,$DNS6_CSV" >> "$TMP"
    : > "$RESOLV_FILE"
    for ip in $new_dhcp6_name_servers; do
      echo "nameserver $ip" >> "$RESOLV_FILE"
    done
  fi
  if [ -n "${new_dhcp6_domain_search:-}" ]; then
    DOM6_CSV=$(printf '%s' "$new_dhcp6_domain_search" | tr ' ' ',')
    echo "dhcp-option=option6:domain-search,$DOM6_CSV" >> "$TMP"
  fi
fi

# Atomically replace and reload dnsmasq
mv -f "$TMP" "$OPTS_FILE"
restart_dnsmasq

# IMPORTANT: do NOT 'exit' here; this file is sourced
EOF

sudo chmod +x /etc/dhcp/dhclient-exit-hooks.d/99-proximus-options
echo "${LAN_IF}" >/etc/router-lan-if

echo "[*] Configure dnsmasq (DHCPv4+DNS, RA+stateless DHCPv6)…"
mkdir -p /etc/dnsmasq.d
cat >/etc/dnsmasq.d/router.conf <<EOF
# Bind to LAN only
interface=${LAN_IF}
bind-dynamic
domain-needed
bogus-priv
dhcp-authoritative

# Local DNS domain
domain=${LAN_DOMAIN}
local=/${LAN_DOMAIN}/
expand-hosts

# Hand the suffix to clients (v4 & v6)
dhcp-option=option:domain-search,${LAN_DOMAIN}
dhcp-option=option6:domain-search,${LAN_DOMAIN}

# Upstream resolvers come from WAN lease (written by hook)
resolv-file=/run/dnsmasq-resolv.conf

# DHCPv4 for LAN
dhcp-range=${LAN_DHCP_START},${LAN_DHCP_END},255.255.255.0,12h
dhcp-option=option:router,${LAN_GW}

# Tag decoder via vendor class (Option 60 starts with '${IPTV_VENDOR_CLASS}')
dhcp-vendorclass=set:decoder,${IPTV_VENDOR_CLASS}*

# Fixed lease for decoder (if provided)
EOF
if [ -n "$DECODER_MAC" ]; then
  echo "dhcp-host=${DECODER_MAC},${DECODER_IP},set:decoder" >>/etc/dnsmasq.d/router.conf
fi
echo "conf-file=/etc/dnsmasq.d/iptv-wan-options.conf" >>/etc/dnsmasq.d/router.conf
cat >>/etc/dnsmasq.d/router.conf <<EOF

# IPv6 Router Advertisements + stateless DHCPv6
enable-ra
dhcp-range=::,constructor:${LAN_IF},ra-stateless,ra-names,12h
EOF
touch /etc/dnsmasq.d/iptv-wan-options.conf /run/dnsmasq-resolv.conf

echo "[*] Configure igmpproxy (multicast from WAN -> LAN)…"
cat >/etc/igmpproxy.conf <<EOF
quickleave
phyint ${WAN_DEV} upstream  ratelimit 0  threshold 1
    altnet 239.192.0.0/16
    altnet 239.255.0.0/16
phyint ${LAN_IF} downstream ratelimit 0  threshold 1
EOF

echo "[*] nftables firewall + NAT (backup at /etc/nftables.conf.bak)"
[ -f /etc/nftables.conf ] && cp -a /etc/nftables.conf /etc/nftables.conf.bak || true
cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f

define WAN = "${WAN_DEV}"
define LAN = "${LAN_IF}"
define LAN_NET = ${LAN_NET}

table inet filter {
  chain input {
    type filter hook input priority 0;
    ct state established,related accept
    iif lo accept

    # Allow local services from LAN only: DHCP/DNS (v4+v6)
    iifname \$LAN udp dport { 67, 547, 53 } accept
    iifname \$LAN tcp dport 53 accept

    # ICMP/ICMPv6 (incl. MLD) to router
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    # IGMP to router
    ip protocol igmp accept

    # SSH from LAN only (uncomment if you install openssh-server)
    iifname \$LAN tcp dport 22 accept

    counter drop
  }

  chain forward {
    type filter hook forward priority 0;
    ct state established,related accept

    # LAN -> anywhere
    iifname \$LAN accept

    # IGMP between LAN and WAN
    ip protocol igmp accept

    # Allow WAN multicast to LAN (IPTV)
    ip daddr { 239.192.0.0/16, 239.255.0.0/16 } accept

    # Default: drop unsolicited WAN->LAN
    iifname \$WAN oifname \$LAN counter drop
  }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100;
    # Do NOT NAT multicast
    ip daddr 224.0.0.0/4 return
    # MASQUERADE LAN IPv4 out WAN
    oifname \$WAN ip saddr \$LAN_NET masquerade
  }
}
EOF
systemctl enable nftables
systemctl restart nftables

echo "[*] Systemd unit for DHCPv6-PD on WAN…"
cat >/etc/systemd/system/dhclient6@.service <<'EOF'
[Unit]
Description=ISC dhclient - DHCPv6 PD on %I
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/sbin/dhclient -6 -P -d -cf /etc/dhcp/dhclient6.conf -sf /etc/dhcp/dhclient-script %I
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now dhclient6@"${WAN_DEV}"

echo "[*] Ensuring networking is up before services…"
systemctl enable networking ifupdown-wait-online.service || true

# dnsmasq waits for LAN device
mkdir -p /etc/systemd/system/dnsmasq.service.d
cat >/etc/systemd/system/dnsmasq.service.d/override.conf <<EOF
[Unit]
Wants=network-online.target sys-subsystem-net-devices-${LAN_IF}.device
After=network-online.target sys-subsystem-net-devices-${LAN_IF}.device
[Service]
Restart=always
RestartSec=3
ExecStartPre=/usr/bin/test -e /sys/class/net/${LAN_IF}
EOF

# igmpproxy waits for WAN+LAN devices
mkdir -p /etc/systemd/system/igmpproxy.service.d
cat >/etc/systemd/system/igmpproxy.service.d/override.conf <<EOF
[Unit]
Wants=network-online.target sys-subsystem-net-devices-${WAN_DEV}.device sys-subsystem-net-devices-${LAN_IF}.device
After=network-online.target sys-subsystem-net-devices-${WAN_DEV}.device sys-subsystem-net-devices-${LAN_IF}.device
BindsTo=sys-subsystem-net-devices-${WAN_DEV}.device sys-subsystem-net-devices-${LAN_IF}.device
[Service]
Restart=always
RestartSec=5
# Block start until WAN has an IPv4 address and LAN link is up
ExecStartPre=/bin/sh -c 'for i in $(seq 1 60); do \
  ip link show ${WAN_DEV} >/dev/null 2>&1 || { sleep 1; continue; }; \
  ip link show ${LAN_IF} >/dev/null 2>&1 || { sleep 1; continue; }; \
  ip -4 addr show dev ${WAN_DEV} | grep -q "inet " || { sleep 1; continue; }; \
  [ "$(cat /sys/class/net/${LAN_IF}/operstate 2>/dev/null)" = "up" ] || { sleep 1; continue; }; \
  exit 0; \
done; echo "WAN/LAN not ready" >&2; exit 1'
EOF

echo "[*] Enable and start core services…"
systemctl daemon-reload
systemctl enable dnsmasq igmpproxy nftables

echo
echo "==========================================================="
echo " Router install complete."
echo
echo " WAN device: ${WAN_DEV}  (VLAN: ${WAN_VLAN:-none})"
echo " LAN (${LAN_IF}): ${LAN_NET} (GW ${LAN_GW})"
[ -n "$DECODER_MAC" ] && echo " Decoder static DHCPv4: ${DECODER_IP} for MAC ${DECODER_MAC}"
echo
echo " Notes:"
echo "  • DSCP untouched; multicast passed via igmpproxy; DHCPv6-PD applied to LAN."
echo "  • If VLAN is set, WAN runs on ${WAN_IF}.${WAN_VLAN}."
echo "  • Reboot the router to apply the changes."
echo "==========================================================="
