# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 3.x (latest release) | Yes |
| Earlier than 3.0 | No |

Fixes ship in a new patch release of the latest version.

## Reporting a vulnerability

Please do not open a public issue, discussion or pull request for a security problem.

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**.

Include:

- the affected version or commit
- steps to reproduce, or a proof of concept
- the impact you expect

We aim to acknowledge reports within 3 business days and to agree on a disclosure date with you. Doorman is maintained by a small team, so please allow reasonable time for a fix before any public disclosure.

## Scope

In scope: the gateway (`gateway-rs`), the web client (`web-client`) and the published container images.

Out of scope: the demo stack (`docker-compose.demo.yml`), which uses published credentials and is meant only for local evaluation.
