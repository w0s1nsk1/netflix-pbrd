# Security policy

## Reporting

Do not open a public issue for a vulnerability that exposes authentication
tokens, routing control, or remote command execution. Contact the maintainer
privately through the security-reporting mechanism configured for the GitHub
repository.

## Deployment

- Use HTTPS for every API exposed outside a private WireGuard network.
- Use a unique random Bearer token for each deployment.
- Restrict API ingress with a firewall in addition to token authentication.
- Store configuration files with mode `0600`.
- Do not place WireGuard private keys in the daemon configuration.
- Review `source_net`, `wan_interface`, peer keys, and UCI section identifiers
  before starting the service.
