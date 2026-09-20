# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅        |

## Reporting a vulnerability

**Please do not open a public issue for security-sensitive bugs.** Report
privately to the repository maintainers (GitHub private vulnerability
reporting on this repository, or the email listed on the npm package page),
and include:

- A description of the flaw and its impact.
- Steps to reproduce (ideally a minimal script).
- Any mitigations you have tried.

We will acknowledge receipt within 3 business days and work toward a fix and
advisory as appropriate.

## Security expectations

This project protects **configured filesystem paths** from supported Pi file
tools and Bubblewrap-sandboxed `bash`/`fd`/`rg` subprocesses. It does not
sandbox the Pi process itself, does not provide DENY pathname secrecy, and
does not defend against kernel exploits, malicious extensions, or a
compromised host. See the README's [Security model](#security-model--read-this)
section for the full threat model and boundaries.

A useful report demonstrates how enforcement is *weakened* below that
boundary (e.g., an unsandboxed fallback, a sandbox failure being swallowed, or
a search path that reads DENY content), not how the documented boundaries can
be crossed by the user themselves.