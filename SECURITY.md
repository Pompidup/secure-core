# Security Policy

## Scope

This policy applies to the `secure-core` crate and all code within this repository. It covers:

- Cryptographic primitive implementations
- Key management and derivation logic
- Memory handling of sensitive data (zeroization, protection)
- Any dependency vulnerability that affects the security guarantees of this crate

Out of scope:

- Issues in upstream dependencies that do not affect this crate's security posture
- Denial-of-service through resource exhaustion (unless it bypasses a security control)

## Supported Versions

| Version | Supported |
| ------- | --------- |
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
| Acknowledgement      | 3 business days |
| Initial triage       | 7 business days |
| Fix or mitigation    | 90 days         |
| Public disclosure    | After fix ships |

We follow a coordinated disclosure model. We ask reporters to allow up to 90 days before public disclosure so that a fix can be prepared and released.

## Recognition

We are happy to credit reporters in release notes (with their permission). If you would like to be credited, please let us know in your report.
