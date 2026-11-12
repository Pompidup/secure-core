# Security Policy

## Scope

This policy applies to the `secure-core` crate of this repository: the Rust library, its C FFI (`include/secure_core.h`) and its JNI bridge. It covers:

- Cryptographic primitive usage (AES-256-GCM, streaming construction, Argon2id recovery)
- The `.enc` and recovery formats and their parsers
- Key derivation (passphrase recovery) and key-material handling inside the core
- Memory handling of sensitive data (zeroization)
- The FFI/JNI boundary (memory safety, error reporting, panics)
- Any dependency vulnerability that affects these guarantees

The mobile application (document storage, backups, authentication, previews, temp files on the device) lives in a separate repository and is **not** covered here. Report app issues through the same private channels below, stating that they concern the app.

Out of scope:

- Attacks requiring root or physical access to the device
- Issues in upstream dependencies that do not affect this crate's security posture
- Social engineering
- Denial-of-service through resource exhaustion (unless it bypasses a security control)

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.5.x (latest) | Yes |
| < 0.5   | No: 0.5.0 fixes [GHSA-43rf-fggr-vcgg](https://github.com/Pompidup/secure-core/security/advisories/GHSA-43rf-fggr-vcgg) and [GHSA-8xr7-q4j5-8p2v](https://github.com/Pompidup/secure-core/security/advisories/GHSA-8xr7-q4j5-8p2v); upgrade |

Only the latest minor release receives security fixes. Releases and their binaries are listed on the [releases page](https://github.com/Pompidup/secure-core/releases).

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, send an email to: **julienauvray28@gmail.com**

Alternatively, you can use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) on this repository.

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

- [Threat Model](docs/threat-model.md)
- [Security Considerations](docs/security-considerations.md)
- [Platform Contract](docs/platform-contract.md): what the core guarantees and what the app must do
- [`.enc` V1 Format](docs/enc-format-v1.md) and [Recovery Format V1](docs/recovery-format-v1.md)
- [FFI ABI V1](docs/ffi-abi-v1.md)
- [Data Lifecycle](docs/data-lifecycle.md)
- [Import Limits](docs/import-limits-v1.md)
- [Security Audit V1](docs/security-audit-v1.md) (historical, pre-0.1.0)

App-side policies (Android/iOS storage, authentication, previews, hardening results) are maintained in the mobile application repository.
