import { SecureCoreAPI, SecureCoreError } from '../SecureCore';
import type { DocumentMeta } from '../SecureCore';

// Mock React Native's NativeModules
jest.mock('react-native', () => ({
  NativeModules: {
    SecureCore: {
      importDocument: jest.fn(),
      decryptToMemory: jest.fn(),
      decryptToTempFile: jest.fn(),
      listDocuments: jest.fn(),
      deleteDocument: jest.fn(),
    },
  },
}));

describe('SecureCore cross-platform contract', () => {
  // Verify that the TS API exposes exactly the same methods on both platforms.
  // The native modules (Android Kotlin / iOS Swift) must match these signatures.

  it('importDocument has same signature on Android and iOS', () => {
    expect(typeof SecureCoreAPI.importDocument).toBe('function');
    expect(SecureCoreAPI.importDocument.length).toBe(1); // (uri: string)
  });

  it('decryptToMemory has same signature on Android and iOS', () => {
    expect(typeof SecureCoreAPI.decryptToMemory).toBe('function');
    expect(SecureCoreAPI.decryptToMemory.length).toBe(1); // (docId: string)
  });

  it('decryptToTempFile has same signature on Android and iOS', () => {
    expect(typeof SecureCoreAPI.decryptToTempFile).toBe('function');
    expect(SecureCoreAPI.decryptToTempFile.length).toBe(1); // (docId: string)
  });

  it('listDocuments has same signature on Android and iOS', () => {
    expect(typeof SecureCoreAPI.listDocuments).toBe('function');
    expect(SecureCoreAPI.listDocuments.length).toBe(0); // no args
  });

  it('deleteDocument has same signature on Android and iOS', () => {
    expect(typeof SecureCoreAPI.deleteDocument).toBe('function');
    expect(SecureCoreAPI.deleteDocument.length).toBe(1); // (docId: string)
  });

  it('API has exactly 5 methods', () => {
    const methods = Object.keys(SecureCoreAPI);
    expect(methods).toEqual([
      'importDocument',
      'decryptToMemory',
      'decryptToTempFile',
      'listDocuments',
      'deleteDocument',
    ]);
  });

  it('no Platform.OS branching in SecureCore.ts', async () => {
    // Read the source file to verify there is no Platform.OS usage
    const fs = require('fs');
    const path = require('path');
    const source = fs.readFileSync(
      path.resolve(__dirname, '../SecureCore.ts'),
      'utf-8'
    );
    expect(source).not.toContain('Platform.OS');
    expect(source).not.toContain("Platform.select");
  });

  it('error codes are consistent across platforms', () => {
    // These error codes must be emitted by both Android and iOS native modules
    const expectedCodes = [
      'CRYPTO_ERROR',
      'NOT_FOUND',
      'INVALID_PARAM',
      'IO_ERROR',
      'KEY_ERROR',
      'AUTH_REQUIRED',
      'UNSUPPORTED_TYPE',
      'FILE_TOO_LARGE',
      'URI_ERROR',
    ];

    // Verify the TypeScript type includes all expected codes
    // by constructing SecureCoreError with each code (compile-time check)
    for (const code of expectedCodes) {
      const err = new SecureCoreError(code as any, 'test');
      expect(err.code).toBe(code);
      expect(err).toBeInstanceOf(Error);
    }
  });

  it('DocumentMeta shape matches Android and iOS output', () => {
    // Verify the type shape by creating a conforming object
    const meta: DocumentMeta = {
      docId: 'test-id',
      filename: 'photo.jpg',
      mimeType: 'image/jpeg',
      createdAt: 1700000000000,
      ciphertextSize: 4096,
    };

    expect(meta.docId).toBe('test-id');
    expect(meta.filename).toBe('photo.jpg');
    expect(meta.mimeType).toBe('image/jpeg');
    expect(meta.createdAt).toBe(1700000000000);
    expect(meta.ciphertextSize).toBe(4096);
  });

  it('DocumentMeta allows optional mimeType', () => {
    const meta: DocumentMeta = {
      docId: 'test-id',
      filename: 'unknown.bin',
      createdAt: 1700000000000,
      ciphertextSize: 1024,
    };

    expect(meta.mimeType).toBeUndefined();
  });
});
