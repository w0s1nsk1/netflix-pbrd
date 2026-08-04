#!/bin/sh
set -eu

binary=$(readlink -f "${1:?binary path is required}")
namespace="netflix-pbrd-$$"
workdir=$(mktemp -d)
pid=""

cleanup() {
	[ -z "$pid" ] || kill "$pid" 2>/dev/null || true
	ip netns del "$namespace" 2>/dev/null || true
	rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

cat >"$workdir/config.json" <<EOF
{
  "role": "controller",
  "state_file": "$workdir/networks.state",
  "api": {
    "listen": "127.0.0.1:18080",
    "token": "01234567890123456789012345678901",
    "report_token": "abcdefghijklmnopqrstuvwxyz012345",
    "allow_insecure_http": true
  },
  "apply": [{
    "driver": "nft-exit",
    "source_net": "10.66.0.0/24",
    "wan_interface": "eth0",
    "chain": "netflix_exit"
  }]
}
EOF

ip netns add "$namespace"
ip netns exec "$namespace" "$binary" -config "$workdir/config.json" &
pid=$!

i=0
while ! ip netns exec "$namespace" nft list table inet netflix_exit >"$workdir/rules" 2>/dev/null; do
	i=$((i + 1))
	[ "$i" -lt 50 ] || { cat "$workdir/rules"; exit 1; }
	sleep 0.1
done
grep -q 'ip saddr 10.66.0.0/24 drop' "$workdir/rules"
grep -q 'ip daddr @destinations accept' "$workdir/rules"

kill "$pid"
wait "$pid"
pid=""
sed -i 's/10.66.0.0\/24/10.67.0.0\/24/' "$workdir/config.json"
ip netns exec "$namespace" "$binary" -config "$workdir/config.json" &
pid=$!
i=0
while ! ip netns exec "$namespace" nft list table inet netflix_exit >"$workdir/rules" 2>/dev/null || ! grep -q 'ip saddr 10.67.0.0/24 drop' "$workdir/rules"; do
	i=$((i + 1))
	[ "$i" -lt 50 ] || exit 1
	sleep 0.1
done
