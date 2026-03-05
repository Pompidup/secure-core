import { NativeModules } from 'react-native';

const { SecureCore } = NativeModules;

export type SecureCoreErrorCode =
  | 'CRYPTO_ERROR'
  | 'NOT_FOUND'
  | 'INVALID_PARAM'
  | 'IO_ERROR'
  | 'KEY_ERROR'
  | 'AUTH_REQUIRED';

export class SecureCoreError extends Error {
  constructor(
    public readonly code: SecureCoreErrorCode,
    message: string
  ) {
    super(message);
    this.name = 'SecureCoreError';
  }
}

export interface DocumentMeta {
  docId: string;
  filename: string;
  mimeType?: string;
  createdAt: number;
  ciphertextSize: number;
}

function isSecureCoreErrorCode(code: string): code is SecureCoreErrorCode {
  return ['CRYPTO_ERROR', 'NOT_FOUND', 'INVALID_PARAM', 'IO_ERROR', 'KEY_ERROR', 'AUTH_REQUIRED'].includes(code);
}

async function wrapNativeCall<T>(call: Promise<T>): Promise<T> {
  try {
    return await call;
  } catch (error: unknown) {
    if (
      error != null &&
      typeof error === 'object' &&
      'code' in error &&
      typeof (error as Record<string, unknown>).code === 'string' &&
      'message' in error &&
      typeof (error as Record<string, unknown>).message === 'string'
    ) {
      const { code, message } = error as { code: string; message: string };
      if (isSecureCoreErrorCode(code)) {
        throw new SecureCoreError(code, message);
      }
    }
    throw error;
  }
}

export const SecureCoreAPI = {
  importDocument(uri: string): Promise<{ docId: string }> {
    return wrapNativeCall(SecureCore.importDocument(uri));
  },

  decryptToMemory(docId: string): Promise<{ bytes: string; mimeType: string }> {
    return wrapNativeCall(SecureCore.decryptToMemory(docId));
  },

  decryptToTempFile(docId: string): Promise<{ uri: string }> {
    return wrapNativeCall(SecureCore.decryptToTempFile(docId));
  },

  listDocuments(): Promise<DocumentMeta[]> {
    return wrapNativeCall(SecureCore.listDocuments());
  },

  deleteDocument(docId: string): Promise<{ deleted: boolean }> {
    return wrapNativeCall(SecureCore.deleteDocument(docId));
  },
};
