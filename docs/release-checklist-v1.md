# Release Checklist - V1.0.0

## Code & Build

- [ ] secure-core Rust crate tagged `v0.1.0` and published
- [ ] Native `.so` built for `arm64-v8a` and `armeabi-v7a`
- [ ] `versionCode = 1` and `versionName = "1.0.0"` in `android/app/build.gradle.kts`
- [ ] Release AAB builds successfully (`./gradlew :app:bundleRelease`)

## Tests

- [ ] Rust unit tests pass (`cargo test --all-features`)
- [ ] Android JNI integration tests pass on emulator
- [ ] Android unit tests pass (`./gradlew :secure-core-android:test`)
- [ ] Hardening tests pass (anti-leak, anti-loss, tamper, perf)
- [ ] Backup policy tests pass (`BackupPolicyTest`)
- [ ] JS/TS smoke tests pass (`npm run test:smoke`)

## Security

- [ ] Backup policy validated (`allowBackup=false`, XML rules, `noBackupFilesDir`)
- [ ] No plaintext written to disk during import (verified by `AntiLeakTest`)
- [ ] Preview purge working (background, release, startup)
- [ ] Tamper detection working (flipped byte -> CryptoError)
- [ ] Biometric auth gate enforced on decrypt operations
- [ ] No unsafe Rust blocks without `// SAFETY:` comment

## Signing & Distribution

- [ ] Production keystore generated and stored securely (NOT in repo)
- [ ] App signed with production keystore
- [ ] Play App Signing enrollment completed
- [ ] CI secrets configured (`KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`)

## Play Store

- [ ] Privacy policy published at a public URL
- [ ] Privacy policy URL added to Play Console
- [ ] Store listing filled (title, descriptions, screenshots)
- [ ] Content rating questionnaire completed
- [ ] Target audience set appropriately
- [ ] App category: Tools

## Documentation

- [ ] `docs/privacy-policy.md` — Contact email filled in
- [ ] `docs/store-listing.md` — Contact email and privacy policy URL filled in
- [ ] `docs/release-signing.md` — Reviewed
- [ ] `docs/auth-policy.md` — Up to date
- [ ] `docs/android-storage-policy.md` — Up to date
- [ ] `docs/data-lifecycle.md` — Up to date
- [ ] `docs/import-limits-v1.md` — Up to date
- [ ] `docs/preview-security-policy.md` — Up to date
- [ ] `docs/hardening-results-v1.md` — Results filled in with dates
- [ ] `docs/rn-api-contract.md` — Up to date
- [ ] `docs/rn-module-setup.md` — Up to date
- [ ] `README.md` — Updated with V1 feature list and setup instructions

## Changelog

- [ ] `CHANGELOG.md` created with V1.0.0 entry
- [ ] Git tag `v1.0.0` created
- [ ] GitHub Release created with AAB artifact

## Post-Release

- [ ] Verify app installs from Play Store on a real device
- [ ] Verify import/decrypt/delete workflow end-to-end
- [ ] Verify biometric prompt appears on decrypt
- [ ] Monitor Play Console for crashes (first 24h)
