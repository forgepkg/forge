# Security policy

## Supported versions

Security fixes are released as a patch release of the most recent minor
release line (currently 1.0.x). Older release lines do not receive them:
upgrade to the latest release to stay supported.

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
- configure `trusted_proxy_cidrs` for your reverse proxies, and let nothing
  else in those ranges reach Forge (on Kubernetes, a NetworkPolicy);
- remove the bootstrap admin once real administrators exist, and its
  password from the environment;
- verify release images before deploying them (`cosign verify` with the exact
  workflow identity printed in each GitHub release's notes).
