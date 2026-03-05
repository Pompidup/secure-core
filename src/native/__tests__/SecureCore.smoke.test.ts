import { NativeModules } from 'react-native';
import { SecureCoreAPI, SecureCoreError } from '../SecureCore';

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

const mockSecureCore = NativeModules.SecureCore as jest.Mocked<typeof NativeModules.SecureCore>;

beforeEach(() => {
  jest.clearAllMocks();
});

test('importDocument resolves with docId', async () => {
  mockSecureCore.importDocument.mockResolvedValue({ docId: 'abc-123' });

  const result = await SecureCoreAPI.importDocument('content://picker/file');

  expect(result).toEqual({ docId: 'abc-123' });
  expect(mockSecureCore.importDocument).toHaveBeenCalledWith('content://picker/file');
});

test('decryptToMemory returns base64 bytes and mimeType', async () => {
  mockSecureCore.decryptToMemory.mockResolvedValue({
    bytes: 'aGVsbG8=',
    mimeType: 'text/plain',
  });

  const result = await SecureCoreAPI.decryptToMemory('abc-123');

  expect(result.bytes).toBe('aGVsbG8=');
  expect(result.mimeType).toBe('text/plain');
});

test('error propagation maps CRYPTO_ERROR to SecureCoreError', async () => {
  mockSecureCore.decryptToMemory.mockRejectedValue({
    code: 'CRYPTO_ERROR',
    message: 'Cryptographic operation failed',
  });

  await expect(SecureCoreAPI.decryptToMemory('bad-id')).rejects.toThrow(SecureCoreError);

  try {
    await SecureCoreAPI.decryptToMemory('bad-id');
  } catch (error) {
    expect(error).toBeInstanceOf(SecureCoreError);
    expect((error as SecureCoreError).code).toBe('CRYPTO_ERROR');
    expect((error as SecureCoreError).message).toBe('Cryptographic operation failed');
  }
});

test('error propagation maps IO_ERROR to SecureCoreError', async () => {
  mockSecureCore.importDocument.mockRejectedValue({
    code: 'IO_ERROR',
    message: 'I/O error',
  });

  try {
    await SecureCoreAPI.importDocument('content://bad');
  } catch (error) {
    expect(error).toBeInstanceOf(SecureCoreError);
    expect((error as SecureCoreError).code).toBe('IO_ERROR');
  }
});

test('unknown error codes are re-thrown as-is', async () => {
  const unknownError = new Error('Something unexpected');
  mockSecureCore.deleteDocument.mockRejectedValue(unknownError);

  await expect(SecureCoreAPI.deleteDocument('x')).rejects.toThrow('Something unexpected');
});

test('listDocuments returns array of DocumentMeta', async () => {
  const docs = [
    {
      docId: 'doc-1',
      filename: 'photo.jpg',
      mimeType: 'image/jpeg',
      createdAt: 1700000000000,
      ciphertextSize: 4096,
    },
    {
      docId: 'doc-2',
      filename: 'report.pdf',
      mimeType: 'application/pdf',
      createdAt: 1700000001000,
      ciphertextSize: 8192,
    },
  ];
  mockSecureCore.listDocuments.mockResolvedValue(docs);

  const result = await SecureCoreAPI.listDocuments();

  expect(result).toHaveLength(2);
  expect(result[0].docId).toBe('doc-1');
  expect(result[1].filename).toBe('report.pdf');
});

test('deleteDocument resolves with deleted true', async () => {
  mockSecureCore.deleteDocument.mockResolvedValue({ deleted: true });

  const result = await SecureCoreAPI.deleteDocument('doc-1');

  expect(result).toEqual({ deleted: true });
});
