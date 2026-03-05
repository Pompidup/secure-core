/**
 * Integration tests for SecureCore RN module.
 *
 * These tests require a running Android emulator or device.
 * They exercise the full native bridge path: JS -> Kotlin -> secure-core-android.
 *
 * RUN MANUALLY: detox test --configuration android.emu.debug
 *
 * Prerequisites:
 * - Android emulator running (or device connected)
 * - App built with: npx react-native run-android
 * - Detox configured in package.json
 */

import { SecureCoreAPI, SecureCoreError } from '../SecureCore';

// Skipped by default — run with: jest --testPathPattern integration
describe.skip('SecureCore integration (requires device)', () => {
  let importedDocId: string;

  test('full lifecycle: import -> list -> decrypt -> delete', async () => {
    // Step 1: Import a document
    // Uses a test image bundled in android/app/src/androidTest/assets/test.png
    const importResult = await SecureCoreAPI.importDocument(
      'content://com.securecore.test.provider/test.png'
    );
    expect(importResult.docId).toBeTruthy();
    importedDocId = importResult.docId;

    // Step 2: List documents — should contain the imported doc
    const docs = await SecureCoreAPI.listDocuments();
    const found = docs.find((d) => d.docId === importedDocId);
    expect(found).toBeDefined();
    expect(found!.ciphertextSize).toBeGreaterThan(0);

    // Step 3: Decrypt to memory — verify base64 content
    const memResult = await SecureCoreAPI.decryptToMemory(importedDocId);
    expect(memResult.bytes.length).toBeGreaterThan(0);
    expect(memResult.mimeType).toBe('image/png');

    // Step 4: Decrypt to temp file — verify URI
    const fileResult = await SecureCoreAPI.decryptToTempFile(importedDocId);
    expect(fileResult.uri).toMatch(/^file:\/\//);

    // Step 5: Delete the document
    const deleteResult = await SecureCoreAPI.deleteDocument(importedDocId);
    expect(deleteResult.deleted).toBe(true);

    // Step 6: List again — should be empty (or not contain deleted doc)
    const docsAfter = await SecureCoreAPI.listDocuments();
    const stillThere = docsAfter.find((d) => d.docId === importedDocId);
    expect(stillThere).toBeUndefined();
  });

  test('decrypt non-existent document rejects with NOT_FOUND', async () => {
    try {
      await SecureCoreAPI.decryptToMemory('non-existent-id');
      fail('Should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(SecureCoreError);
      expect((error as SecureCoreError).code).toBe('NOT_FOUND');
    }
  });
});
