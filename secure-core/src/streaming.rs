use std::io::{Read, Write};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::crypto::{generate_nonce, Dek};
use crate::error::SecureCoreError;
use crate::format::{EncHeader, FLAG_STREAM_FINAL_CHUNK, FORMAT_VERSION_V1, FORMAT_VERSION_V2};

/// Default chunk size: 64 KB of plaintext per chunk.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// GCM auth tag size in bytes.
const TAG_SIZE: usize = 16;

/// Upper bound on a single chunk's encoded length (ciphertext + tag).
/// A legitimate writer never exceeds `CHUNK_SIZE + TAG_SIZE`; anything
/// beyond is corruption or a malicious payload trying to force a huge
/// allocation via the 4-byte length prefix.
const MAX_CHUNK_ENCODED_LEN: usize = CHUNK_SIZE + TAG_SIZE;

/// Header flag bits a stream reader of this build understands. Any other
/// bit makes `decrypt_stream` reject the stream: in V1.1 the header is not
/// authenticated, and in V2 an unknown bit means semantics this reader
/// cannot apply.
const KNOWN_STREAM_FLAGS: u16 = FLAG_STREAM_FINAL_CHUNK;

/// High bit of the chunk-index AAD that marks the final chunk of a stream.
/// The bit is reserved; valid chunk indices are in `0..LAST_CHUNK_AAD_MARKER`.
const LAST_CHUNK_AAD_MARKER: u32 = 0x8000_0000;

/// Maximum chunk index permitted in a stream (top bit reserved as marker).
pub const MAX_STREAM_CHUNKS: u32 = LAST_CHUNK_AAD_MARKER - 1;

/// Maximum total plaintext bytes a single stream can carry, derived from
/// [`MAX_STREAM_CHUNKS`] × [`CHUNK_SIZE`] ≈ 128 TiB. Well beyond any mobile
/// use case; callers that hit this limit should split their data across
/// multiple streams with independent DEKs.
///
/// Unlike the in-memory [`crate::crypto::MAX_PLAINTEXT_SIZE`] (4 GiB on 64-bit),
/// streaming is only bound by this ceiling because it never holds the full
/// plaintext in memory. The two limits coexist by design: `encrypt_bytes`
/// is for small payloads that can be fully buffered, `encrypt_stream` is
/// the right tool for anything larger.
pub const MAX_STREAM_PLAINTEXT_SIZE: u64 = (MAX_STREAM_CHUNKS as u64) * (CHUNK_SIZE as u64);

/// AES-256-GCM state for the chunks of one stream: the cipher, the base
/// nonce and the AAD prefix fixed by the format version.
///
/// Chunk AAD = `aad_prefix || BE32(chunk_index | final marker)`, where
/// `aad_prefix` is empty in V1.1 and the full header in V2
/// (docs/enc-format-v2.md, ADR-003).
struct ChunkCipher {
    cipher: Aes256Gcm,
    base_nonce: [u8; 12],
    aad_prefix: Vec<u8>,
}

impl ChunkCipher {
    /// `header_bytes` are the header exactly as written to / read from the
    /// stream; they enter the AAD only for V2.
    fn new(dek: &Dek, header: &EncHeader, header_bytes: &[u8]) -> Result<Self, SecureCoreError> {
        let aad_prefix = match header.version {
            FORMAT_VERSION_V1 => Vec::new(),
            FORMAT_VERSION_V2 => header_bytes.to_vec(),
            other => {
                return Err(SecureCoreError::UnsupportedVersion {
                    found: other,
                    max_supported: FORMAT_VERSION_V2,
                })
            }
        };
        let cipher = Aes256Gcm::new_from_slice(dek.as_bytes())
            .map_err(|e| SecureCoreError::CryptoError(e.to_string()))?;
        Ok(Self {
            cipher,
            base_nonce: header.nonce,
            aad_prefix,
        })
    }

    fn aad(&self, chunk_index: u32, is_last: bool) -> Vec<u8> {
        let marker = if is_last { LAST_CHUNK_AAD_MARKER } else { 0 };
        let mut aad = Vec::with_capacity(self.aad_prefix.len() + 4);
        aad.extend_from_slice(&self.aad_prefix);
        aad.extend_from_slice(&(chunk_index | marker).to_be_bytes());
        aad
    }

    fn seal(
        &self,
        chunk_index: u32,
        is_last: bool,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SecureCoreError> {
        let nonce = nonce_for_chunk(&self.base_nonce, chunk_index);
        let aad = self.aad(chunk_index, is_last);
        self.cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|e| SecureCoreError::CryptoError(e.to_string()))
    }

    fn open(
        &self,
        chunk_index: u32,
        is_last: bool,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecureCoreError> {
        let nonce = nonce_for_chunk(&self.base_nonce, chunk_index);
        let aad = self.aad(chunk_index, is_last);
        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                let cause = if is_last {
                    "truncated stream or invalid key/tampered final chunk"
                } else {
                    "invalid key or tampered data"
                };
                SecureCoreError::CryptoError(format!(
                    "decryption failed on chunk {chunk_index}: {cause}"
                ))
            })
            .map(Zeroizing::new)
    }
}

/// Metadata returned after a streaming encrypt/decrypt operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamMetadata {
    pub chunks: u32,
    pub total_plaintext_bytes: u64,
    pub total_ciphertext_bytes: u64,
}

/// Derives a per-chunk nonce by XORing the chunk index into the last 4 bytes of the base nonce.
fn nonce_for_chunk(base_nonce: &[u8; 12], chunk_index: u32) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let idx_bytes = chunk_index.to_be_bytes();
    nonce[8] ^= idx_bytes[0];
    nonce[9] ^= idx_bytes[1];
    nonce[10] ^= idx_bytes[2];
    nonce[11] ^= idx_bytes[3];
    nonce
}

/// Encrypts data from `input` into `output` using chunked AES-256-GCM.
///
/// Writes a V2 header (version 2, [`FLAG_STREAM_FINAL_CHUNK`]) followed by
/// individually encrypted chunks. Every chunk authenticates the full header,
/// its index and, for the last one, a final marker, so decrypt can prove the
/// header is genuine and the stream was not truncated (docs/enc-format-v2.md).
pub fn encrypt_stream<R: Read, W: Write>(
    input: R,
    output: W,
    dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError> {
    encrypt_stream_impl(input, output, dek, generate_nonce(), FORMAT_VERSION_V2)
}

/// Deterministic V2 encoder used to produce reproducible golden files.
/// Given the same `base_nonce`, `dek`, and input bytes, it emits a
/// byte-identical stream — enabling the compat pack to ship streaming
/// vectors that other implementations can verify.
#[cfg(any(test, feature = "_test-vectors"))]
pub fn encrypt_stream_with_nonce_test<R: Read, W: Write>(
    input: R,
    output: W,
    dek: &Dek,
    base_nonce: [u8; 12],
) -> Result<StreamMetadata, SecureCoreError> {
    encrypt_stream_impl(input, output, dek, base_nonce, FORMAT_VERSION_V2)
}

/// Deterministic V1.1 encoder, kept only to regenerate the frozen V1.1
/// golden files and to test that 1.x still reads V1.1 streams. Production
/// code never writes V1.1.
#[cfg(any(test, feature = "_test-vectors"))]
pub fn encrypt_stream_v1_1_with_nonce_test<R: Read, W: Write>(
    input: R,
    output: W,
    dek: &Dek,
    base_nonce: [u8; 12],
) -> Result<StreamMetadata, SecureCoreError> {
    encrypt_stream_impl(input, output, dek, base_nonce, FORMAT_VERSION_V1)
}

fn encrypt_stream_impl<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    dek: &Dek,
    base_nonce: [u8; 12],
    version: u16,
) -> Result<StreamMetadata, SecureCoreError> {
    let mut header = EncHeader::new_stream_v2(base_nonce);
    header.version = version;
    let header_bytes = header.to_bytes();

    output.write_all(&header_bytes)?;

    let cipher = ChunkCipher::new(dek, &header, &header_bytes)?;

    // Plaintext buffers are wiped when dropped or replaced.
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut pending: Option<Zeroizing<Vec<u8>>> = None;
    let mut chunk_index: u32 = 0;
    let mut total_plaintext: u64 = 0;
    let mut total_ciphertext: u64 = header_bytes.len() as u64;
    let mut first_iter = true;

    loop {
        let bytes_read = read_exact_or_eof(&mut input, &mut buf)?;

        // EOF reached after having buffered at least one chunk: exit and
        // finalize the pending chunk as the last one.
        if bytes_read == 0 && !first_iter {
            break;
        }

        // Flush the previously buffered chunk as non-final now that a new one
        // has arrived behind it.
        if let Some(prev) = pending.take() {
            write_chunk(
                &cipher,
                chunk_index,
                false,
                &prev,
                &mut output,
                &mut total_plaintext,
                &mut total_ciphertext,
            )?;
            chunk_index = checked_next_index(chunk_index)?;
        }

        pending = Some(Zeroizing::new(buf[..bytes_read].to_vec()));
        first_iter = false;

        if bytes_read < CHUNK_SIZE {
            break;
        }
    }

    // Flush the final buffered chunk with the terminal marker. `pending` is
    // always `Some` here: either we buffered a real chunk, or we buffered an
    // empty vec for the empty-input case.
    let final_chunk = pending.expect("pending chunk always set before final flush");
    write_chunk(
        &cipher,
        chunk_index,
        true,
        &final_chunk,
        &mut output,
        &mut total_plaintext,
        &mut total_ciphertext,
    )?;
    chunk_index = checked_next_index(chunk_index)?;

    output.flush()?;

    Ok(StreamMetadata {
        chunks: chunk_index,
        total_plaintext_bytes: total_plaintext,
        total_ciphertext_bytes: total_ciphertext,
    })
}

fn write_chunk<W: Write>(
    cipher: &ChunkCipher,
    chunk_index: u32,
    is_last: bool,
    plaintext: &[u8],
    output: &mut W,
    total_plaintext: &mut u64,
    total_ciphertext: &mut u64,
) -> Result<(), SecureCoreError> {
    let ciphertext_with_tag = cipher.seal(chunk_index, is_last, plaintext)?;

    let chunk_len = ciphertext_with_tag.len() as u32;
    output.write_all(&chunk_len.to_le_bytes())?;
    output.write_all(&ciphertext_with_tag)?;

    *total_plaintext += plaintext.len() as u64;
    *total_ciphertext += 4 + ciphertext_with_tag.len() as u64;
    Ok(())
}

fn checked_next_index(current: u32) -> Result<u32, SecureCoreError> {
    let next = current
        .checked_add(1)
        .ok_or_else(|| SecureCoreError::InvalidParameter("too many chunks".into()))?;
    if next > MAX_STREAM_CHUNKS {
        return Err(SecureCoreError::InvalidParameter(format!(
            "too many chunks: limit is {MAX_STREAM_CHUNKS}"
        )));
    }
    Ok(next)
}

/// Decrypts a V2 or V1.1 chunked stream from `input` into `output`.
///
/// The header must carry exactly [`FLAG_STREAM_FINAL_CHUNK`]; truncation is
/// then detected via the terminal AAD marker. Streams without the flag
/// (legacy V1.0 layout) or with unknown flag bits are rejected with
/// [`SecureCoreError::InvalidFormat`] before any plaintext is written. In
/// V2 the whole header is also part of every chunk's AAD, so any header
/// modification, including a downgrade to V1.1, fails authentication.
///
/// Legacy V1.0 streams (secure-core < 0.3.0) cannot be read by this version
/// at all: re-encrypt them with secure-core 0.5.x or 0.6.x before upgrading.
pub fn decrypt_stream<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    dek: &Dek,
) -> Result<StreamMetadata, SecureCoreError> {
    let mut header_buf = vec![0u8; 25];
    input
        .read_exact(&mut header_buf)
        .map_err(|_| SecureCoreError::InvalidFormat("failed to read stream header".into()))?;

    let header = EncHeader::from_bytes(&header_buf)?;
    // A flag bit this build does not know comes from corruption or tampering
    // (V1.1, unauthenticated header) or from a future writer whose semantics
    // we cannot apply (V2). Refuse rather than guess.
    let unknown_flags = header.flags & !KNOWN_STREAM_FLAGS;
    if unknown_flags != 0 {
        return Err(SecureCoreError::InvalidFormat(format!(
            "stream header has unknown flag bits {unknown_flags:#06x}"
        )));
    }
    if header.flags & FLAG_STREAM_FINAL_CHUNK == 0 {
        return Err(SecureCoreError::InvalidFormat(
            "stream lacks FLAG_STREAM_FINAL_CHUNK (legacy V1.0 layout or downgraded header); \
             legacy streams are no longer readable, re-encrypt them with secure-core 0.6"
                .into(),
        ));
    }

    // V2: the header bytes exactly as read enter every chunk's AAD.
    let cipher = ChunkCipher::new(dek, &header, &header_buf)?;

    let mut chunk_index: u32 = 0;
    let mut total_plaintext: u64 = 0;
    let mut total_ciphertext: u64 = header_buf.len() as u64;

    // Buffer the most recently read chunk; we only know it's final once the
    // next length-prefix read hits EOF. This lets us apply the right AAD.
    let mut pending: Option<Vec<u8>> = None;

    loop {
        let mut len_buf = [0u8; 4];
        let read_next = match input.read_exact(&mut len_buf) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => false,
            Err(e) => return Err(e.into()),
        };

        if !read_next {
            // Stream exhausted. If we had a buffered chunk, decrypt it as the
            // final chunk; otherwise the input contained no chunks at all.
            match pending.take() {
                Some(buf) => {
                    let plaintext = cipher.open(chunk_index, true, &buf)?;
                    output.write_all(&plaintext)?;
                    total_plaintext += plaintext.len() as u64;
                    chunk_index = checked_next_index(chunk_index)?;
                }
                None => {
                    return Err(SecureCoreError::InvalidFormat(
                        "stream is missing its final chunk".into(),
                    ));
                }
            }
            break;
        }

        let chunk_len = u32::from_le_bytes(len_buf) as usize;
        if chunk_len < TAG_SIZE {
            return Err(SecureCoreError::InvalidFormat(
                "chunk too small to contain auth tag".into(),
            ));
        }
        if chunk_len > MAX_CHUNK_ENCODED_LEN {
            // Reject attacker-declared lengths before allocating — otherwise
            // a malicious blob could force vec![0; 4GB] and abort the
            // process on low-memory devices.
            return Err(SecureCoreError::InvalidFormat(format!(
                "chunk length {chunk_len} exceeds maximum {MAX_CHUNK_ENCODED_LEN}"
            )));
        }

        let mut chunk_buf = vec![0u8; chunk_len];
        input.read_exact(&mut chunk_buf).map_err(|_| {
            SecureCoreError::InvalidFormat("unexpected EOF while reading chunk data".into())
        })?;
        total_ciphertext += 4 + chunk_len as u64;

        // A new chunk has arrived behind the buffered one: flush the buffered
        // chunk as non-final, then replace it.
        if let Some(prev) = pending.take() {
            let plaintext = cipher.open(chunk_index, false, &prev)?;
            output.write_all(&plaintext)?;
            total_plaintext += plaintext.len() as u64;
            chunk_index = checked_next_index(chunk_index)?;
        }

        pending = Some(chunk_buf);
    }

    output.flush()?;

    Ok(StreamMetadata {
        chunks: chunk_index,
        total_plaintext_bytes: total_plaintext,
        total_ciphertext_bytes: total_ciphertext,
    })
}

/// Reads exactly `buf.len()` bytes, or fewer if EOF is reached.
/// Returns the number of bytes actually read.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const TEST_KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];

    #[test]
    fn test_encrypt_stream_with_nonce_is_deterministic() {
        let dek = Dek::new(TEST_KEY);
        let plaintext = b"deterministic stream vector";
        let nonce = [0xAB_u8; 12];

        let mut blob1 = Vec::new();
        encrypt_stream_with_nonce_test(Cursor::new(plaintext), &mut blob1, &dek, nonce).unwrap();

        let mut blob2 = Vec::new();
        encrypt_stream_with_nonce_test(Cursor::new(plaintext), &mut blob2, &dek, nonce).unwrap();

        assert_eq!(
            blob1, blob2,
            "same key+nonce+plaintext must produce byte-identical streams"
        );
    }

    #[test]
    fn test_max_stream_plaintext_size_matches_chunk_math() {
        assert_eq!(
            MAX_STREAM_PLAINTEXT_SIZE,
            (MAX_STREAM_CHUNKS as u64) * (CHUNK_SIZE as u64)
        );
    }

    #[test]
    fn test_streaming_limit_is_strictly_larger_than_in_memory_limit() {
        // Documents the design invariant: when a payload exceeds the
        // in-memory cap, streaming is guaranteed to have headroom.
        assert!(
            (crate::crypto::MAX_PLAINTEXT_SIZE as u64) < MAX_STREAM_PLAINTEXT_SIZE,
            "in-memory limit ({}) must remain below streaming limit ({})",
            crate::crypto::MAX_PLAINTEXT_SIZE,
            MAX_STREAM_PLAINTEXT_SIZE
        );
    }

    #[test]
    fn test_nonce_derivation_unique() {
        let base = [0u8; 12];
        let n0 = nonce_for_chunk(&base, 0);
        let n1 = nonce_for_chunk(&base, 1);
        let n2 = nonce_for_chunk(&base, 2);
        assert_ne!(n0, n1);
        assert_ne!(n1, n2);
        assert_eq!(n0, base); // XOR with 0 is identity
    }

    #[test]
    fn test_nonce_derivation_deterministic() {
        let base = [0xAA; 12];
        let n1 = nonce_for_chunk(&base, 42);
        let n2 = nonce_for_chunk(&base, 42);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_stream_roundtrip_unit() {
        let dek = Dek::new(TEST_KEY);
        let plaintext = b"hello streaming";

        let mut encrypted = Vec::new();
        let enc_meta = encrypt_stream(Cursor::new(plaintext), &mut encrypted, &dek).unwrap();
        assert_eq!(enc_meta.chunks, 1);
        assert_eq!(enc_meta.total_plaintext_bytes, plaintext.len() as u64);

        let mut decrypted = Vec::new();
        let dec_meta = decrypt_stream(Cursor::new(&encrypted), &mut decrypted, &dek).unwrap();
        assert_eq!(decrypted, plaintext);
        assert_eq!(dec_meta.chunks, 1);
        assert_eq!(dec_meta.total_plaintext_bytes, plaintext.len() as u64);
    }

    #[test]
    fn test_stream_empty() {
        let dek = Dek::new(TEST_KEY);
        let plaintext = b"";

        let mut encrypted = Vec::new();
        let enc_meta = encrypt_stream(Cursor::new(plaintext), &mut encrypted, &dek).unwrap();
        // Empty input still produces 1 chunk (with 0 bytes of plaintext)
        assert_eq!(enc_meta.chunks, 1);
        assert_eq!(enc_meta.total_plaintext_bytes, 0);

        let mut decrypted = Vec::new();
        decrypt_stream(Cursor::new(&encrypted), &mut decrypted, &dek).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
