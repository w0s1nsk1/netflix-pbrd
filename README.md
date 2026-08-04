# netflix-pbrd

`netflix-pbrd` learns the rotating IPv4 addresses used by Netflix applications
from their real DNS traffic and keeps policy-based routing rules synchronized.
It is designed for WireGuard gateways, OpenWrt routers, small embedded Linux
devices, and public exit servers.

This project is not affiliated with or endorsed by Netflix.

## Recommended topology

```text
LAN device -> edge -> inner WireGuard -> exit router -> Internet
                       (transported by an outer WireGuard hub)
```

This is the preferred three-host layout. The edge DNS proxy learns addresses
before returning DNS answers and reports them synchronously to the exit. The
outer hub transports only the
encrypted UDP session between the edge and exit peers; it does not need
Netflix routes, destination AllowedIPs, or a `netflix-pbrd` process. The exit
router runs the controller and applies a fail-closed exit policy. The edge
agent installs the learned Netflix marks on the inner WireGuard interface.
If the exit's default route is not its desired WAN, configure one static source
policy routing `source_net` to that WAN; the exit driver then restricts
forwarding and NAT to learned Netflix destinations.

The nested OpenWrt example uses `nft-exit`, which owns a dedicated nftables
table and atomically updates its destination set. Regular Linux exits can use
the equivalent iptables-based `linux-exit` driver.

The example configs use `172.31.255.1/30` for the exit and
`172.31.255.2/30` for the edge. Configure the inner exit peer with the edge LAN
in AllowedIPs, and configure the edge peer with `0.0.0.0/0` without installing
an operating-system default route. An MTU around 1340 is a conservative
starting point for WireGuard inside WireGuard.

## Quick start

WireGuard must already connect the edge and exit. On a build host, generate one
bundle; the command creates matching random API tokens without printing them:

```sh
netflix-pbrd generate -topology nested \
  -edge-peer 'EXIT_WIREGUARD_PUBLIC_KEY' \
  -output netflix-pbrd-bundle
```

Transfer the matching binary and config to each host. Installation is one
command per host and automatically detects systemd, OpenWrt, or Entware:

```sh
# On the OpenWrt exit:
sudo ./netflix-pbrd-linux-arm64 install -config exit.json

# On the Entware edge:
sudo ./netflix-pbrd-linux-armv7 install -config edge.json
```

Configure LAN clients, DHCP, or a gateway redirect so both UDP and TCP DNS reach
the generated edge `dns_proxy.listen` address.

Verify the result on both hosts, then run the end-to-end test on the edge:

```sh
netflix-pbrd doctor
netflix-pbrd status
netflix-pbrd smoke-test
```

`smoke-test` resolves a trusted Netflix name through the configured DNS proxy,
waits for synchronous apply/report, and shows the actual `ip route get` path of
the learned address.

## Advanced topologies

### Controller, transit relay, and edge

```text
LAN device -> edge router -> WireGuard controller -> relay router -> Internet
```

The edge proxies DNS, learns trusted Netflix answers and CNAME targets, and
synchronously reports each learned address before returning it to the client.
There is no endpoint bootstrap list. The edge installs destination routes and
packet marks. The controller routes reported destinations to the relay peer,
and the OpenWrt relay uses a static source policy for the dedicated controller
WireGuard network. The relay does not poll the controller: because only learned
Netflix destinations are routed into that peer, its final-hop forwarding and
WAN policy can be ready before any DNS answer is returned.

### Client and public exit server

```text
LAN device -> WireGuard client -> public exit server -> Internet
```

The public server combines the controller API and `linux-exit` driver. The
client uses the `linux-edge` driver. WireGuard itself is configured separately;
this daemon manages only destination policy, routes, and firewall rules.

## Properties

- One static Go binary for `amd64`, `arm64`, and `armv7`.
- DNS learning recognizes Netflix-owned suffixes, future app-version hostnames,
  Netflix service ELBs, and CNAME chains without enumerating endpoint names.
- Monotonic state: previously observed addresses are retained across DNS
  rotation and process restarts.
- Authenticated agent reports contain only addresses learned by that agent;
  fetched controller state is never echoed back.
- Desired, applied, and last-reported state are tracked separately. Failed
  applies and reports are retried without requiring a DNS change.
- Applied driver state is periodically verified or reinstalled, defaulting to
  every five minutes, to recover from external route or firewall removal.
  OpenWrt checks UCI and service state first, avoiding commits and reloads when
  both are healthy.
- Separate read and report bearer tokens with constant-time comparison.
- Agent reports accept public IPv4 `/32` hosts only. Broader trusted prefixes
  are limited to `/24` or narrower, and `max_networks` defaults to 4096.
- TLS required by default for a listening API. Plain HTTP must be explicitly
  enabled and should only be used on a private WireGuard address.
- Drivers for WireGuard transit routing, Linux edge PBR, OpenWrt PBR, and a
  Linux public exit.

## Build

```sh
make test
make build VERSION=v0.1.0
```

Artifacts are written to `dist/`.

## Advanced configuration

Choose and adapt one of the files in [`configs/`](configs/):

- `nested-relay-controller.example.json`
- `nested-edge.example.json`
- `controller-relay.example.json`
- `edge.example.json`
- `openwrt-relay-static.example.sh`
- `public-server.example.json`
- `public-client.example.json`

Generate separate read and report tokens with at least 32 random bytes each:

```sh
openssl rand -hex 32
openssl rand -hex 32
```

Never commit a real token, WireGuard private key, public address inventory, or
production configuration.

Validate a configuration without changing networking state:

```sh
netflix-pbrd -config /etc/netflix-pbrd.json -check
```

The learning proxy must run on the edge that controls the client's first
route. Both UDP and TCP DNS traffic from application devices must reach
`dns_proxy.listen`. The proxy returns a trusted Netflix answer only after its
addresses have been applied and reported successfully; otherwise it returns
SERVFAIL. Do not redirect the proxy's own upstream traffic back to the learning
port.

As an alternative to `upstream`, configure `doh_url`. The proxy then sends
DNS-message POST requests with the original client in `X-Real-IP`. Add only the
proxy address to AdGuard Home's `trusted_proxies`; AdGuard can then attribute
query-log entries and client policies to the real device instead of the proxy.

## Operations

`doctor` checks the configured interface and peer, controller API, UDP/TCP DNS,
owned nftables or iptables state, policy rule, learned route, and agent report
progress. `status` reads the daemon's atomic runtime status file and includes
the last apply/report times and last error.

```sh
netflix-pbrd doctor
netflix-pbrd status
netflix-pbrd smoke-test -name android.prod.cloud.netflix.com
```

Cleanup removes only tables, chains, policy rules, routes, WireGuard AllowedIPs
and UCI values named by the loaded configuration. It never flushes a complete
ruleset or the main route table:

```sh
sudo netflix-pbrd cleanup
sudo netflix-pbrd uninstall -yes
sudo netflix-pbrd uninstall -yes -purge  # also removes config and state
```

Without `-purge`, uninstall preserves the configuration and learned state.
Existing files replaced by `install` receive timestamped backups.

A separate OpenWrt transit relay does not run the daemon. Adapt and run
`configs/openwrt-relay-static.example.sh` once after its WireGuard network and
WAN PBR interface exist. Its WAN firewall zone must have masquerading enabled.
Apply this policy before enabling the edge DNS proxy.

`linux-edge.input_interface` selects the incoming LAN interface and supports an
iptables `+` suffix; it defaults to `br+`. `linux-edge.next_hop` is optional.
Omit it for a point-to-point WireGuard
interface so routes are installed directly with `dev <interface>`. The driver
installs only a default route in its dedicated policy table; destination
selection remains scoped to `source_net` by the mangle mark and `ip rule`.
Set `reapply_interval` to change periodic driver reconciliation; the minimum is
30 seconds and the default is five minutes.

## Public server requirements

- A working WireGuard tunnel with forwarding enabled.
- A valid TLS certificate for the controller API.
- Firewall access to the API port restricted to known client addresses where
  possible.
- The `linux-exit` source network must match the WireGuard client subnet.

The exit driver inserts an early forwarding chain, accepts synchronized
destinations, then drops every other forwarded packet from `source_net`.
Replies and unrelated traffic return to the base firewall. Its NAT chain
masquerades only synchronized destinations. This
fail-closed behavior prevents a permissive base firewall from turning the host
into an unrestricted VPN gateway.

## Operational notes

State files are intentionally monotonic. Locally learned hosts are stored in a
separate `<state_file>.learned` file so failed reports survive restarts. Remove
a controller state file only
when you explicitly want to forget historical destinations. The controller
then rebuilds the set from DNS answers actually requested by Netflix
applications. After a successful fetch, agents replace their startup state
with the current controller set instead of retaining obsolete bootstrap data.

Run the daemon as root because route, WireGuard, iptables, and UCI updates need
network-administration privileges. Keep the JSON configuration readable only
by root because it contains the API token.
