# Contributing to secure-core

Thank you for your interest in contributing to secure-core.

## Getting Started

1. Fork the repository.
2. Clone your fork locally.
3. Create a feature branch from `main`.
4. Make your changes, ensuring all tests pass.
5. Submit a pull request.

## Development Requirements

- Rust stable toolchain (installed automatically via `rust-toolchain.toml`)
- `rustfmt` and `clippy` components

## Code Standards

- Run `cargo fmt --all` before committing.
- Run `cargo clippy --all-targets --all-features` and fix all warnings.
- All public APIs must include documentation.
- All changes must include tests.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new encryption primitive
fix: correct key derivation edge case
docs: update API reference
```

## Security

If you discover a security vulnerability, **do not** open a public issue. Instead, follow the process described in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
