# Beta Process - V1.0.0

## Overview

- **Target:** 20-50 internal testers
- **Channel:** Google Play Internal Testing track
- **Duration:** 2 weeks minimum before production release
- **Entry criteria:** All items in `release-checklist-v1.md` marked done (except Play Store publication)

## Setup

1. Create an Internal Testing track in Play Console
2. Upload the signed AAB
3. Add testers by email (Google Group or individual emails)
4. Share the opt-in link with testers

## Manual Test Scenarios

Each tester should complete the following scenarios and report pass/fail:

### Import

| # | Scenario | Expected Result |
|---|----------|-----------------|
| 1 | Import JPEG image (< 5 MB) | Success, appears in document list |
| 2 | Import PDF document (< 20 MB) | Success, appears in document list |
| 3 | Import plain text note | Success, appears in document list |
| 4 | Import unsupported file (e.g., .mp4) | Error message, no crash |
| 5 | Import file > 50 MB | Error message "file too large", no crash |

### Preview

| # | Scenario | Expected Result |
|---|----------|-----------------|
| 6 | Preview imported JPEG | Image displays correctly |
| 7 | Preview imported PDF | PDF renders correctly |
| 8 | Close preview, check cache | No temp files remain in cache |

### Lifecycle

| # | Scenario | Expected Result |
|---|----------|-----------------|
| 9 | Delete a document | Removed from list, cannot be recovered |
| 10 | Restart app after import | Document list is consistent, all docs present |
| 11 | Force-kill app during preview, relaunch | No orphaned temp files, list intact |

### Authentication

| # | Scenario | Expected Result |
|---|----------|-----------------|
| 12 | Biometric prompt on decrypt | Fingerprint/face unlocks successfully |
| 13 | Cancel biometric prompt | Returns to app, no crash, can retry |
| 14 | Fail biometric 5 times (lockout) | Falls back to PIN/pattern/password |
| 15 | Wait 5+ minutes, decrypt again | Biometric prompt reappears (session expired) |

### Edge Cases

| # | Scenario | Expected Result |
|---|----------|-----------------|
| 16 | Import with low storage (< 100 MB free) | Graceful error or success |
| 17 | Switch to another app during import | Import completes in background |
| 18 | Rotate screen during preview | Preview survives rotation |

## Bug Report Template

When reporting a bug, include:

```
**App version:** (e.g., 1.0.0, versionCode 1)
**Device model:** (e.g., Pixel 7, Samsung Galaxy S23)
**Android version:** (e.g., Android 14, API 34)

**Steps to reproduce:**
1.
2.
3.

**Expected behavior:**


**Actual behavior:**


**Screenshots/screen recording:** (if applicable)

**Does it reproduce consistently?** Yes / No / Sometimes
```

## Exit Criteria

The beta is considered successful when:

- All 18 test scenarios pass on at least 3 different device models
- Crash rate < 1% across all testers
- No P0 or P1 bugs remain open
- At least 10 testers have completed the full test suite
