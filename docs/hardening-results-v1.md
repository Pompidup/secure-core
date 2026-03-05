# Hardening Test Results - V1

## Test Suite Overview

All tests run as Android instrumented tests on an emulator (API 31, x86_64).
CI job: `hardening-tests` (runs on every merge to `main`).

## Anti-Leak Tests

| Test | Expected | Status |
|------|----------|--------|
| `testImport_noClearTextInPublicStorage` | No plaintext in /sdcard/ or external cache after import | Pending |
| `testPreviewClosed_noClearTextInCache` | Preview dir empty after releasePreview() | Pending |
| `testAppBackground_previewsPurged` | purgeAllPreviews() clears all temp files | Pending |

## Anti-Loss Tests

| Test | Expected | Status |
|------|----------|--------|
| `testOrphanedEncFile_reconciledOnStartup` | Orphaned .enc moved to quarantine by ReconciliationService | Pending |
| `testOrphanedTmpFile_cleanedOnStartup` | Old .enc.tmp files cleaned by cleanOrphanedTempFiles() | Pending |
| `testOrphanedMetadata_reconciledOnStartup` | Metadata without .enc file is deleted | Pending |
| `testKillDuringPreview_cleanupOnRestart` | Expired preview files purged on next launch | Pending |

## Tamper Detection Tests

| Test | Expected | Status |
|------|----------|--------|
| `testTamperedEncFile_decryptFails` | Flipped byte -> CryptoError (AES-GCM auth tag mismatch) | Pending |
| `testTruncatedEncFile_decryptFails` | Truncated ciphertext -> error (not crash) | Pending |
| `testEmptyEncFile_decryptFails` | Empty .enc -> error (not crash) | Pending |

## Performance Tests

| Test | Expected | Status |
|------|----------|--------|
| `testEncryptDecrypt_50mb_withinMemoryBudget` | Peak RAM < 200 MB for 50 MB file | Pending |
| `testEncryptDecrypt_50mb_withinTimeLimit` | Encrypt + decrypt < 15 seconds | Pending |

## Known Limitations (V1)

- **Crash during import:** A brutal process kill can leave an orphaned `.enc` file. The `ReconciliationService` quarantines it on next startup. No plaintext is ever written to disk.
- **Crash during preview:** A process kill can leave a `.preview` temp file in the cache dir. `purgeExpiredPreviews()` cleans files older than 5 minutes on next launch.
- **Memory budget:** The current implementation loads the entire file into memory for encryption/decryption. The 200 MB budget accommodates the 50 MB limit (plaintext + ciphertext + overhead). Streaming encryption is planned for V2.
- **Performance on emulator:** The 15-second time limit is calibrated for CI emulators. Real devices are significantly faster.

## CI Artifacts

Test reports are uploaded as GitHub Actions artifacts (`hardening-test-results`) on every run. Reports include:
- HTML test report: `build/reports/androidTests/`
- JUnit XML results: `build/outputs/androidTest-results/`
