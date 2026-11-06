# Changelog

All notable changes to `netflix-pbrd` are documented here.

## [0.1.1] - 2026-11-06

Fixes found while deploying on a real three-node setup (edge + exit, both
behind a shared WireGuard hub).

### Fixed

- `linux-edge` no longer mutates the WireGuard peer's `AllowedIPs` on every
  reconcile cycle (`wg set ... allowed-ips ...`). On a tunnel shared with
  other traffic this silently overwrote a hand-managed `AllowedIPs` list on
  a timer. Routing into the tunnel still works via `ip rule` + `iptables`
  mangle; the operator must ensure the peer's `AllowedIPs` already covers
  the learned destinations (e.g. `0.0.0.0/0`), set once, out of band.
- `smoke-test` no longer fails with `dns: buffer size too small`. The probe
  query now sends EDNS0 (4096-byte buffer); without it, any reply with more
  than a couple of A/AAAA records (routine for Netflix hostnames) came back
  larger than the classic 512-byte UDP assumption.
- `.ipk` packaging produced a byte-for-byte `.deb` (`ar -cr debian-binary
  control.tar.gz data.tar.gz`), which real `opkg` rejects with "Malformed
  package file". A genuine opkg `.ipk` is a gzip-compressed tar of the same
  three members, no `ar` wrapper — fixed and verified with `opkg install` on
  OpenWrt 24.10.

### Added

- `dns_proxy.doh_ca_file`: trust one extra PEM CA for the DoH upstream
  without installing it into the host's system-wide trust store. Useful for
  a self-signed/internal resolver (e.g. a home AdGuard Home instance).

## [0.1.0] - 2026-08-06

First release focused on a usable, fail-closed deployment for Netflix
destination policy routing.

### Added

- DNS control-plane learning for Netflix hostnames, CNAME chains, service ELBs,
  iOS and Android app endpoints.
- Controller and agent roles with separate read and report bearer tokens.
- Nested WireGuard, public exit, Linux edge, Linux exit, nftables, OpenWrt PBR,
  and static OpenWrt relay topologies.
- `generate`, `install`, `doctor`, `status`, `smoke-test`, `cleanup`, and
  `uninstall` commands for onboarding and operations.
- Persistent `learned`, `applied`, and `reported` state with retry and runtime
  health status.
- Debian, Entware, OpenWrt IPK, and OpenWrt 25.12 APK v3 packaging in CI.
- GitHub Release artifacts for tagged versions.

### Security and reliability

- Fail-closed nftables and Linux exit policies.
- Exact ownership checks for `ip rule` entries, including embedded text
  fallbacks without JSON support.
- Cleanup and uninstall now propagate firewall, route, UCI, and service errors.
- Entware stop verifies both the PID file and `/proc/<pid>/exe` before sending
  a signal.
- Android diagnostics verify the policy rule, PREROUTING hook, learned
  destination rule, and policy-table route.
- CIDR validation limits agent reports to host routes and bounds the learned
  set size.

### Validation

- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- CI package installation and archive validation for DEB, IPK, and APK v3.

[0.1.1]: https://github.com/w0s1nsk1/netflix-pbrd/releases/tag/v0.1.1
[0.1.0]: https://github.com/w0s1nsk1/netflix-pbrd/releases/tag/v0.1.0
