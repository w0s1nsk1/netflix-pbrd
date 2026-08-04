#!/bin/sh
set -eu

# The controller routes only learned Netflix destinations to this dedicated
# WireGuard network. The relay policy therefore stays static and has no poll gap.
WG_NETWORK="wg_controller"
SOURCE_NET="192.168.8.0/24"
WAN_PBR_INTERFACE="wan"

uci -q delete firewall.netflix_relay_zone || true
uci set firewall.netflix_relay_zone=zone
uci set firewall.netflix_relay_zone.name=netflix_wg
uci set firewall.netflix_relay_zone.network="$WG_NETWORK"
uci set firewall.netflix_relay_zone.input=REJECT
uci set firewall.netflix_relay_zone.output=ACCEPT
uci set firewall.netflix_relay_zone.forward=REJECT
uci set firewall.netflix_relay_zone.family=ipv4

uci -q delete firewall.netflix_relay_forward || true
uci set firewall.netflix_relay_forward=forwarding
uci set firewall.netflix_relay_forward.src=netflix_wg
uci set firewall.netflix_relay_forward.dest=wan

uci -q delete pbr.netflix_relay || true
uci set pbr.netflix_relay=policy
uci set pbr.netflix_relay.name='Netflix controller relay'
uci set pbr.netflix_relay.interface="$WAN_PBR_INTERFACE"
uci set pbr.netflix_relay.src_addr="$SOURCE_NET"
uci set pbr.netflix_relay.chain=prerouting

uci commit firewall
uci commit pbr
/etc/init.d/firewall reload
/etc/init.d/pbr reload
