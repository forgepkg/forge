# Security policy

## Supported versions

Security fixes go into the latest release. While the major version is 0, only
the most recent minor release line (currently 0.1.x) receives them.

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability.

Report it privately through GitHub: open the repository's **Security** tab and
choose **Report a vulnerability**. This opens a private security advisory that
only the maintainers can see.

Include what you can:

- the affected version (`GET /version`) and deployment details that matter
  (reverse proxy, auth realms in use);
- steps to reproduce, or a proof of concept;
- the impact as you understand it.

You will get an acknowledgement within a few working days. A fix is prepared
in the private advisory and released with a changelog entry, and the reporter
is credited unless they prefer otherwise.

## Hardening guidance

Production settings are described in [docs/deployment.md](docs/deployment.md).
The most important ones:

- serve Forge only behind TLS, with an https `public_base_url`;
- enable secret encryption at rest;
- configure `trusted_proxy_cidrs` for your reverse proxies;
- remove the bootstrap admin once real administrators exist.
