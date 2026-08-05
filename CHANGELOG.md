# Changelog

All notable changes to `netflix-pbrd` are documented here.

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

[0.1.0]: https://github.com/w0s1nsk1/netflix-pbrd/releases/tag/v0.1.0
