# iOS Smoke Test

Manual smoke test checklist for the SecureCore React Native module on iOS.

## Prerequisites

- Xcode with iOS 15+ simulator or physical device
- App built and running: `npx react-native run-ios`
- For biometrics: physical device with Face ID or Touch ID enrolled

## Test 1: Full Document Lifecycle

1. **Import a JPEG**
   - Tap "Import" in the app
   - Select a JPEG from the photo library or Files
   - Verify: success callback returns `{ docId: "..." }`
   - Verify: no crash, no error in Metro console

2. **List documents**
   - Call `listDocuments()`
   - Verify: array contains the imported document
   - Verify: `filename`, `mimeType` ("image/jpeg"), `createdAt`, `ciphertextSize` are present

3. **Decrypt to memory**
   - Call `decryptToMemory(docId)`
   - Verify: returns `{ bytes: "<base64>", mimeType: "image/jpeg" }`
   - Verify: base64 decodes to valid JPEG data

4. **Decrypt to temp file and preview**
   - Call `decryptToTempFile(docId)`
   - Verify: returns `{ uri: "file:///..." }`
   - Open the URI with QuickLook or an image viewer
   - Verify: image displays correctly

5. **Delete document**
   - Call `deleteDocument(docId)`
   - Verify: returns `{ deleted: true }`

6. **List is empty**
   - Call `listDocuments()`
   - Verify: array is empty (or no longer contains the deleted doc)

## Test 2: Biometric Authentication (physical device only)

1. **Trigger decrypt** (if AuthGate is wired)
   - Call `decryptToMemory(docId)` for a document
   - Verify: Face ID / Touch ID prompt appears

2. **Cancel authentication**
   - Tap "Cancel" on the biometric prompt
   - Verify: error with code `AUTH_REQUIRED` is returned

3. **Retry**
   - Call decrypt again
   - Authenticate successfully
   - Verify: decrypted data is returned

## Test 3: Error Handling

1. **Non-existent document**
   - Call `decryptToMemory("non-existent-id")`
   - Verify: error with code `NOT_FOUND`
   - Verify: error message contains the docId

2. **Invalid URI**
   - Call `importDocument("not-a-valid-uri://???")`
   - Verify: error with code `INVALID_PARAM` or `IO_ERROR`

3. **Delete non-existent**
   - Call `deleteDocument("non-existent-id")`
   - Verify: no crash (may return `{ deleted: true }` or error depending on implementation)

## Test 4: Background Purge

1. Import a document and decrypt to temp file
2. Background the app (press Home)
3. Foreground the app
4. Check that temp files in `NSTemporaryDirectory/previews/` have been cleaned
   - Can verify via Xcode's device file browser or `NSFileManager` debug logging

## Expected Results

All operations should complete without crash. Error codes returned to JS should match the documented codes in `docs/rn-cross-platform.md`.
