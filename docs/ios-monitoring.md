# iOS Monitoring

## Crash Reporting

### Primary: Xcode Organizer

- **Source**: App Store Connect / Xcode Organizer > Crashes
- **Coverage**: All App Store and TestFlight users
- **Delay**: Typically available within 24h of crash occurrence
- **Access**: Any team member with App Store Connect access

### Optional: Firebase Crashlytics

- If integrated, provides real-time crash reporting with:
  - Symbolicated stack traces
  - Device/OS distribution
  - Breadcrumb logs (non-sensitive only)
  - Crash-free users percentage

### Sensitive Data Policy

- **NEVER** log document contents, filenames, or docIds in crash reports
- **NEVER** include DEK material or wrapsJson in breadcrumbs
- **NEVER** attach user files to crash reports
- **ALLOWED**: Error codes (`CRYPTO_ERROR`, `NOT_FOUND`, etc.), operation names, file sizes
- **ALLOWED**: Device model, iOS version, app version, memory usage
- Verify with each release: review sample crash reports for accidental data exposure

## Metrics & Thresholds

| Metric | Target | Alert |
|---|---|---|
| Crash-free users | > 99.5% | < 99% triggers investigation |
| Crash rate per version | < 0.5% | > 1% blocks next release |
| ANR / hang rate | < 0.5% | > 1% triggers investigation |
| App launch time | < 2s | > 5s triggers investigation |

## Alert Triggers

### P0 (Immediate)

- Crash rate > 1% within first 24h of a release
- Any crash in `DocumentService.importDocument` or `DocumentService.decryptDocument`
- Any crash related to Keychain access (`KeyManagerError`)
- Data loss reported by user (file imported but not in list)

### P1 (Within 24h)

- Crash rate > 0.5% sustained over 48h
- Crashes in preview lifecycle (`SecurePreviewManager`, `QuickLookPreviewController`)
- Memory-related crashes on specific device models

### P2 (Next Sprint)

- Crashes in edge cases (low storage, backgrounding)
- UI-only crashes not affecting data integrity

## Monitoring Checklist (Post-Release)

### First 24 Hours

- [ ] Check Xcode Organizer for crash reports
- [ ] Verify crash-free users > 99%
- [ ] Check TestFlight feedback for issues
- [ ] Verify no sensitive data in crash logs

### First Week

- [ ] Review crash trends by device model and iOS version
- [ ] Check App Store reviews for data-related issues
- [ ] Verify memory usage patterns (Xcode Organizer > Metrics)
- [ ] Check disk usage growth (Organizer > Disk Writes)

### Ongoing

- [ ] Weekly crash report review
- [ ] Monthly crash-free rate trend analysis
- [ ] Compare iOS and Android crash rates for parity
- [ ] Review new iOS version betas for compatibility issues

## Incident Response

1. **Triage**: Determine if crash affects data integrity (P0) or is cosmetic (P2)
2. **Reproduce**: Use device model and iOS version from crash report
3. **Fix**: Priority fix in next build
4. **Validate**: Run full hardening test suite before release
5. **Deploy**: Expedited review if P0 (Apple offers expedited review for critical fixes)
6. **Communicate**: Update TestFlight "What to Test" notes if applicable
