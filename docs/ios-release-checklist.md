# iOS Release Checklist - V1.0.0

## Code & Build

- [ ] secure-core Rust xcframework generated from tag `v0.1.0`
- [ ] xcframework includes `arm64` (device) and `arm64` (simulator) slices
- [ ] Swift Package builds with `swift build` (no warnings)
- [ ] `CFBundleShortVersionString = "1.0.0"` aligned with Android `versionName`
- [ ] `CFBundleVersion = "1"` aligned with Android `versionCode`

## Tests

- [ ] Swift bridge tests pass (`swift test`)
- [ ] Hardening tests pass (anti-leak, anti-loss, tamper, perf)
- [ ] Preview lifecycle tests pass
- [ ] DocumentService orchestration tests pass
- [ ] JS/TS cross-platform contract tests pass (`npx jest SecureCore.crossplatform`)
- [ ] JS/TS smoke tests pass (`npm run test:smoke`)
- [ ] Manual smoke test completed (see `docs/smoke-test-ios.md`)

## Security

- [ ] Backup policy validated: all files have `.isExcludedFromBackupKey = true`
- [ ] No plaintext written to disk during import (verified by `AntiLeakTests`)
- [ ] Preview purge working (background via `willResignActive`, release, startup)
- [ ] Tamper detection working (flipped byte -> `CRYPTO_ERROR`)
- [ ] Biometric auth via Keychain access control (FaceID / TouchID + passcode fallback)
- [ ] No sensitive data in crash reports or logs

## Privacy & Compliance

- [ ] `PrivacyInfo.xcprivacy` included in the bundle (required since Spring 2024)
- [ ] `NSPrivacyCollectedDataTypes` is empty (no data collection)
- [ ] `NSPrivacyAccessedAPITypes` declares filesystem access if applicable
- [ ] `NSFaceIDUsageDescription` set in Info.plist

## Signing & Distribution

- [ ] App signed with Apple Distribution certificate
- [ ] Provisioning profile includes App ID and entitlements
- [ ] Keychain Sharing entitlement configured (if cross-app access needed)
- [ ] Archive validated in Xcode Organizer (no errors)
- [ ] Uploaded to App Store Connect via Xcode or `xcrun altool`

## App Store

- [ ] Privacy policy published at a public URL
- [ ] App Store Connect: privacy nutrition labels filled (no data collected)
- [ ] App Store Connect: store listing filled (title, descriptions, screenshots)
- [ ] App Store Connect: age rating questionnaire completed
- [ ] App Store Connect: app category set (Utilities)
- [ ] No third-party SDK declarations needed (no analytics, no ads)

## Documentation

- [ ] `docs/ios-storage-policy.md` -- Up to date
- [ ] `docs/ios-preview-policy.md` -- Up to date
- [ ] `docs/ios-hardening-results.md` -- Results filled with dates
- [ ] `docs/rn-cross-platform.md` -- Up to date
- [ ] `docs/smoke-test-ios.md` -- Up to date
- [ ] `docs/ios-beta-process.md` -- Up to date
- [ ] `docs/ios-monitoring.md` -- Up to date

## Changelog

- [ ] `CHANGELOG.md` updated with `[1.0.0-ios]` entry
- [ ] Git tag `v1.0.0-ios` created
- [ ] GitHub Release created

## Post-Release

- [ ] Verify app installs from TestFlight on a real device
- [ ] Verify import/decrypt/delete workflow end-to-end
- [ ] Verify FaceID/TouchID prompt appears on decrypt
- [ ] Verify iCloud restore scenario (data inaccessible = expected, Keychain lost)
- [ ] Monitor Xcode Organizer crash reports (first 48h)
- [ ] Crash rate < 0.5% after first 1000 installs
