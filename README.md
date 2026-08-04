# netflix-pbrd

`netflix-pbrd` keeps policy-based routing rules synchronized with the rotating
IPv4 addresses returned by Netflix service endpoints. It is designed for
WireGuard gateways, OpenWrt routers, small embedded Linux devices, and public
exit servers.

This project is not affiliated with or endorsed by Netflix.

## Topologies

### Nested WireGuard relay

```text
LAN device -> edge -> inner WireGuard -> exit router -> Internet
                       (transported by an outer WireGuard hub)
```

This is the preferred three-host layout. The outer hub transports only the
encrypted UDP session between the edge and exit peers; it does not need
Netflix routes, destination AllowedIPs, or a `netflix-pbrd` process. The exit
router runs the controller and applies one static source policy for the edge
LAN. The edge agent installs the rotating Netflix routes on the inner
WireGuard interface.

The example configs use `172.31.255.1/30` for the exit and
`172.31.255.2/30` for the edge. Configure the inner exit peer with the edge LAN
in AllowedIPs, and configure the edge peer with `0.0.0.0/0` without installing
an operating-system default route. An MTU around 1340 is a conservative
starting point for WireGuard inside WireGuard.

### Controller, transit relay, and edge

```text
LAN device -> edge router -> WireGuard controller -> relay router -> Internet
```

The controller resolves service domains and publishes a monotonic network set.
The edge installs destination routes and packet marks. The controller routes
those destinations to the relay peer, and the OpenWrt relay applies its WAN PBR
and firewall policy.

### Client and public exit server

```text
LAN device -> WireGuard client -> public exit server -> Internet
```

The public server combines the controller API and `linux-exit` driver. The
client uses the `linux-edge` driver. WireGuard itself is configured separately;
this daemon manages only destination policy, routes, and firewall rules.

## Properties

- One static Go binary for `amd64`, `arm64`, and `armv7`.
- Monotonic state: previously observed addresses are retained across DNS
  rotation and process restarts.
- Authenticated agent reports merge edge history back into the controller, so
  every hop converges on the same destination set.
- Changes are applied only when the network set changes.
- Bearer-token authentication with constant-time token comparison.
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

## Configuration

Choose and adapt one of the files in [`configs/`](configs/):

- `nested-relay-controller.example.json`
- `nested-edge.example.json`
- `controller-relay.example.json`
- `edge.example.json`
- `openwrt-relay.example.json`
- `public-server.example.json`
- `public-client.example.json`

Generate a control-plane token with at least 32 random bytes:

```sh
openssl rand -hex 32
```

Never commit a real token, WireGuard private key, public address inventory, or
production configuration.

Validate a configuration without changing networking state:

```sh
netflix-pbrd -config /etc/netflix-pbrd.json -check
```

## Install

On a regular Linux controller or public server:

```sh
install -m 0755 dist/netflix-pbrd-linux-amd64 /usr/local/sbin/netflix-pbrd
install -m 0600 configs/public-server.example.json /etc/netflix-pbrd.json
install -m 0644 packaging/systemd/netflix-pbrd.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now netflix-pbrd
```

For OpenWrt, install the `arm64` binary as `/usr/sbin/netflix-pbrd`, copy the
procd service from `packaging/openwrt/`, and enable it through `/etc/init.d`.

For Entware on an ARMv7 gateway, install the binary as
`/opt/sbin/netflix-pbrd`, the configuration under `/opt/etc/`, and use the
startup scripts in `packaging/entware/`. `S47wg-relay` is an example inner
WireGuard interface setup; replace its public key and endpoint before use.

`linux-edge.next_hop` is optional. Omit it for a point-to-point WireGuard
interface so routes are installed directly with `dev <interface>`.

## Public server requirements

- A working WireGuard tunnel with forwarding enabled.
- A valid TLS certificate for the controller API.
- Firewall access to the API port restricted to known client addresses where
  possible.
- The `linux-exit` source network must match the WireGuard client subnet.

The exit driver only permits and NATs destinations in the synchronized set. It
does not turn the host into an unrestricted VPN gateway.

## Operational notes

State files are intentionally monotonic. Remove a state file only when you
explicitly want to forget historical destinations. Restarting the service then
rebuilds the set from configured seed networks and current DNS answers.

Run the daemon as root because route, WireGuard, iptables, and UCI updates need
network-administration privileges. Keep the JSON configuration readable only
by root because it contains the API token.
