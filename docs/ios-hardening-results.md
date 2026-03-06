# iOS Hardening Test Results

**Date**: 2026-03-06
**Platform**: macOS (arm64e, SPM `swift test`)
**Total hardening tests**: 11

## Anti-Leak Tests (AntiLeakTests.swift)

| Test | Result | Notes |
|---|---|---|
| `testImport_noClearTextInDocumentsDir` | PASS | Scans store dir and previews dir for plaintext sentinel; none found |
| `testPreviewClosed_noTempFileRemaining` | PASS | `sc_previews/` empty after `releasePreview()` |
| `testAppBackground_previewsPurged` | PASS | `purgeAllPreviews()` clears all files (simulates `willResignActive`) |

## Anti-Loss Tests (AntiLossTests.swift)

| Test | Result | Notes |
|---|---|---|
| `testKillDuringImport_noCorruptedFile` | PASS | Task cancellation after 100ms; no orphaned .enc without metadata, no .enc.tmp remnants |
| `testReconciliation_afterSimulatedCrash` | PASS | Orphaned .enc.tmp (>5 min old) cleaned by `cleanOrphanedTempFiles()` |
| `testReconciliation_orphanedEncMovedToQuarantine` | PASS | .enc without metadata moved to quarantine by `ReconciliationService` |
| `testAtomicWrite_noPartialFiles` | PASS | 512KB write is atomic; no .enc.tmp remnants; data matches exactly |

## Tamper Detection Tests (TamperTests.swift)

| Test | Result | Notes |
|---|---|---|
| `testTamperedEncFile_decryptFails` | PASS | Flipping 1 byte in .enc causes `decryptionFailed` (maps to `CRYPTO_ERROR` in RN) |
| `testTamperedEncFile_originalNotAffected` | PASS | Tampering one doc does not affect other docs |

## Performance Tests (PerfTests.swift)

| Test | Result | Notes |
|---|---|---|
| `testEncryptDecrypt_50MB_memoryBudget` | PASS | ~248MB peak delta for 50MB file (budget: 300MB). XOR mock overhead; real AES will be lower |
| `testEncryptDecrypt_50MB_timeLimit` | PASS | ~5.3s on macOS (limit: 60s simulator / 20s device) |

## CI Configuration

| Test category | When to run | Environment |
|---|---|---|
| Anti-leak tests | Every PR | Simulator / macOS (SPM) |
| Anti-loss tests | Every PR | Simulator / macOS (SPM) |
| Tamper tests | Every PR | Simulator / macOS (SPM) |
| Perf tests | Optional / nightly | Physical device preferred; simulator with x3 tolerance |

To run hardening tests only:
```bash
swift test --filter "AntiLeak|AntiLoss|Tamper|Perf"
```

To run fast tests only (exclude 50MB perf tests):
```bash
swift test --filter "AntiLeak|AntiLoss|Tamper"
```

## Known Limitations (V1 iOS)

1. **Crash during import**: If the process is killed between `writeDocument` and `save(metadata)`, an orphaned .enc file may remain. `ReconciliationService.reconcile()` moves it to quarantine at next launch.

2. **Crash during preview**: If killed while a preview temp file exists, it persists until next `purgeAllPreviews()` or `purgeExpiredPreviews(maxAge: 300)` call.

3. **Memory budget**: The 300MB budget is measured with the XOR mock crypto lib. Real AES-GCM via the xcframework should use less memory. Budget should be re-validated once the real crypto lib is integrated.

4. **No streaming encryption**: Currently the entire plaintext is loaded into memory for encryption. For files >100MB, a streaming API should be considered in V2.

5. **Simulator-only biometric testing**: Biometric authentication tests require a physical device. Simulator tests use mock key managers that bypass biometric prompts.
