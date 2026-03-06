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

## iOS

- [ ] xcframework generated from tag `v0.1.0` (arm64 device + simulator)
- [ ] Swift bridge tests pass (`swift test`)
- [ ] iOS hardening tests pass (anti-leak, anti-loss, tamper, perf)
- [ ] `PrivacyInfo.xcprivacy` included in bundle
- [ ] Backup exclusion validated (`.isExcludedFromBackupKey`)
- [ ] FaceID/TouchID + passcode fallback working
- [ ] App signed with Apple Distribution certificate
- [ ] App Store privacy nutrition labels filled (no data collected)
- [ ] `CFBundleShortVersionString` = "1.0.0" (aligned with Android `versionName`)
- [ ] See `docs/ios-release-checklist.md` for full iOS-specific checklist

## Cross-Platform Alignment

- [ ] Both platforms use the same `versionName` / `CFBundleShortVersionString` ("1.0.0")
- [ ] JS/TS cross-platform contract tests pass (`npx jest SecureCore.crossplatform`)
- [ ] Same error codes on both platforms (verified by contract tests)
- [ ] `CHANGELOG.md` has entries for both `[1.0.0]` (Android) and `[1.0.0-ios]`
- [ ] Release notes are consistent across Play Store and App Store

## Post-Release

### Android
- [ ] Verify app installs from Play Store on a real device
- [ ] Verify import/decrypt/delete workflow end-to-end
- [ ] Verify biometric prompt appears on decrypt
- [ ] Monitor Play Console for crashes (first 24h)

### iOS
- [ ] Verify app installs from TestFlight on a real device
- [ ] Verify import/decrypt/delete workflow end-to-end
- [ ] Verify FaceID/TouchID prompt appears on decrypt
- [ ] Verify iCloud restore scenario (empty state, no crash)
- [ ] Monitor Xcode Organizer for crashes (first 48h)
