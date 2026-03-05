# Monitoring - V1

## Crash Reporting

### Recommended: Firebase Crashlytics

Firebase Crashlytics provides real-time crash reporting integrated with Play Console.

**Setup:**
1. Add Firebase to the project (`google-services.json`)
2. Add Crashlytics Gradle plugin and SDK
3. Verify no sensitive data in crash reports (see below)

**Alternative:** Play Console's built-in Android Vitals (no SDK needed, but less detailed).

### Sensitive Data Audit

Before enabling any crash reporting, verify:

- [ ] No document content appears in stack traces
- [ ] No encryption keys appear in log output
- [ ] No file paths containing document IDs are logged at INFO level or above
- [ ] No biometric callback data is logged
- [ ] `SecureCoreError` messages are generic (no crypto internals)

Run a manual audit:
```bash
# Search for potential log leaks in the codebase
grep -rn "Log\.\|println\|Timber\." --include="*.kt" android/
```

## Alerting

| Metric | Threshold | Action |
|--------|-----------|--------|
| Crash-free rate | < 99% (crash rate > 1%) | Immediate investigation |
| ANR rate | > 0.5% | Performance investigation |
| P0 crash (crypto/data leak) | Any occurrence | Hotfix within 48h (see `hotfix-process.md`) |

## Dashboards

| Dashboard | URL | What to monitor |
|-----------|-----|-----------------|
| Play Console > Android Vitals | [Play Console](https://play.google.com/console) | Crash rate, ANR rate, by device/OS |
| Play Console > Ratings & Reviews | [Play Console](https://play.google.com/console) | User complaints about data loss or crashes |
| Firebase Crashlytics (if enabled) | [Firebase Console](https://console.firebase.google.com) | Stack traces, affected users, trends |

## What We Do NOT Monitor

SecureCore has **no telemetry, no analytics, and no network communication**. We cannot and do not:

- Track user behavior
- Count documents imported
- Measure feature usage
- Collect device information beyond crash reports

This is by design. The only monitoring data comes from:
1. **Play Console Android Vitals** (opt-in by users, aggregated by Google)
2. **Firebase Crashlytics** (if added, opt-in, crash data only)

## First Week Post-Release Checklist

- [ ] Monitor crash-free rate daily in Play Console
- [ ] Check for 1-star reviews mentioning crashes or data loss
- [ ] Verify no sensitive data in Crashlytics reports (if enabled)
- [ ] Review ANR rate (should be < 0.1%)
- [ ] If crash rate > 1%: trigger P0/P1 investigation
