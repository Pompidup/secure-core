# iOS Beta Process

## TestFlight Phases

### Phase 1: Internal Testing (1 week)

- **Audience**: Development team only (up to 100 internal testers)
- **Distribution**: Automatic via App Store Connect internal group
- **Objective**: Validate core flows, catch regressions
- **No App Review required** for internal testers

### Phase 2: External Testing (2 weeks)

- **Audience**: Up to 10,000 external testers
- **Distribution**: Via public TestFlight link or email invitation
- **Requires**: App Review (Beta App Review, typically 24-48h)
- **Objective**: Real-world usage patterns, device diversity, edge cases
- **Feedback**: Via TestFlight built-in feedback (screenshots + notes)

## Validation Scenarios

### Core Flows (same as Android)

1. Import JPEG from Photos -> list -> decrypt -> preview -> delete -> list empty
2. Import PDF from Files -> preview via QuickLook -> delete
3. Import 5 documents -> list shows all 5 -> delete all -> list empty
4. Import document -> force-quit app -> reopen -> document still accessible

### iOS-Specific Scenarios

5. **FaceID -> cancel -> retry**: Tap cancel on FaceID prompt, verify `AUTH_REQUIRED` error, retry and authenticate successfully
6. **FaceID lockout -> passcode fallback**: Fail FaceID 5 times, verify passcode prompt appears, authenticate with passcode
7. **TouchID flow** (older devices): Same as FaceID scenarios but with fingerprint
8. **iCloud restore**: Back up device, restore from iCloud, verify documents are inaccessible (expected behavior -- Keychain keys are not restored from iCloud backup by default). User should see empty state, not a crash.
9. **App backgrounding**: Open a preview, background the app, foreground, verify preview temp files were purged
10. **Low storage**: Import when device storage is nearly full, verify graceful error (`IO_ERROR`)
11. **iPad multitasking**: Use app in Split View, verify no layout issues during import/preview

### Error Handling

12. Decrypt non-existent document -> `NOT_FOUND` error in JS
13. Import invalid file (0 bytes) -> appropriate error
14. Import file > 50MB -> `FILE_TOO_LARGE` or size-appropriate handling

## Bug Report Template

```
**App Version**: [e.g. 1.0.0 (1)]
**Device Model**: [e.g. iPhone 15 Pro]
**iOS Version**: [e.g. 17.4.1]
**TestFlight Build**: [e.g. build 42]

**Steps to Reproduce**:
1. ...
2. ...

**Expected Result**: ...
**Actual Result**: ...

**Crash Log** (if applicable):
[Attach from Settings > Privacy > Analytics > Analytics Data]

**Screenshots**: [attach]
```

## Go / No-Go Criteria

### Must Pass (blockers)

- All core flows (1-4) work on iPhone and iPad
- FaceID/TouchID authentication works (scenarios 5-7)
- No crashes in any scenario
- Crash rate < 0.5% across all testers

### Should Pass (non-blockers for V1)

- iCloud restore shows empty state gracefully (scenario 8)
- Low storage error handling (scenario 10)
- iPad multitasking (scenario 11)

## Timeline

| Day | Activity |
|---|---|
| D0 | Upload build to App Store Connect |
| D0 | Internal testing begins |
| D1 | Submit for Beta App Review (external) |
| D3 | External testing begins (after review) |
| D7 | Internal testing complete, fix blockers |
| D14 | External testing complete |
| D15 | Final build for App Store submission |
