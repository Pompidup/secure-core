# Security Policy

## Scope

This policy applies to the `secure-core` crate and the SecureCore Android application. It covers:

- Cryptographic primitive implementations
- Key management and derivation logic
- Memory handling of sensitive data (zeroization, protection)
- Document storage and backup policy
- Authentication and session management
- Preview lifecycle and temp file handling
- Any dependency vulnerability that affects the security guarantees

Out of scope:

- Attacks requiring root or physical access to the device
- Issues in upstream dependencies that do not affect this crate's security posture
- Social engineering
- Denial-of-service through resource exhaustion (unless it bypasses a security control)

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, send an email to: **security@pompidup.com**

Please include:

1. A description of the vulnerability.
2. Steps to reproduce or a proof of concept.
3. The affected version(s).
4. Any potential impact assessment.

## Response SLA

| Phase                | Timeline        |
| -------------------- | --------------- |
| Acknowledgement      | 48 hours        |
| Initial triage       | 1 week          |
| P0 fix (crypto/leak) | 48 hours        |
| P1 fix (crash)       | 1 week          |
| Public disclosure    | After fix ships |

We follow a coordinated disclosure model. We ask reporters to allow time for a fix before public disclosure.

## Recognition

We are happy to credit reporters in release notes (with their permission). If you would like to be credited, please let us know in your report.

## Security Design Documentation

- [Data Lifecycle](docs/data-lifecycle.md)
- [Android Storage Policy](docs/android-storage-policy.md)
- [Auth Policy](docs/auth-policy.md)
- [Preview Security Policy](docs/preview-security-policy.md)
- [Import Limits](docs/import-limits-v1.md)
- [Hardening Results](docs/hardening-results-v1.md)
