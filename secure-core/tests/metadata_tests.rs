use secure_core::error::SecureCoreError;
use secure_core::metadata::{DocumentMetadata, WrappedDek};

fn sample_metadata() -> DocumentMetadata {
    DocumentMetadata {
        doc_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        filename: "photo.jpg".into(),
        mime_type: Some("image/jpeg".into()),
        created_at: 1709654400,
        plaintext_size: Some(102400),
        ciphertext_size: 102816,
        content_hash: Some([0xAB; 32]),
        wrapped_dek: WrappedDek {
            device_wrap: vec![0x01, 0x02, 0x03, 0x04],
            recovery_wrap: None,
            wrap_algorithm: "AES-KWP".into(),
        },
    }
}

#[test]
fn test_metadata_serialization_roundtrip() {
    let meta = sample_metadata();
    let json = serde_json::to_string_pretty(&meta).unwrap();
    let deserialized: DocumentMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, deserialized);
}

#[test]
fn test_metadata_json_fields_present() {
    let meta = sample_metadata();
    let json = serde_json::to_string(&meta).unwrap();

    assert!(json.contains("\"doc_id\""));
    assert!(json.contains("\"filename\""));
    assert!(json.contains("\"mime_type\""));
    assert!(json.contains("\"created_at\""));
    assert!(json.contains("\"wrapped_dek\""));
    assert!(json.contains("\"wrap_algorithm\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn test_metadata_optional_fields_omitted() {
    let meta = DocumentMetadata {
        doc_id: "abc-123".into(),
        filename: "doc.pdf".into(),
        mime_type: None,
        created_at: 1709654400,
        plaintext_size: None,
        ciphertext_size: 500,
        content_hash: None,
        wrapped_dek: WrappedDek {
            device_wrap: vec![0xFF],
            recovery_wrap: None,
            wrap_algorithm: "RSA-OAEP".into(),
        },
    };

    let json = serde_json::to_string(&meta).unwrap();
    assert!(!json.contains("\"mime_type\""));
    assert!(!json.contains("\"plaintext_size\""));
    assert!(!json.contains("\"content_hash\""));
    assert!(!json.contains("\"recovery_wrap\""));

    // Roundtrip still works
    let deserialized: DocumentMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, deserialized);
}

#[test]
fn test_metadata_validate_ok() {
    let meta = sample_metadata();
    assert!(meta.validate().is_ok());
}

#[test]
fn test_metadata_validate_empty_doc_id() {
    let mut meta = sample_metadata();
    meta.doc_id = String::new();

    let err = meta.validate().unwrap_err();
    assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
}

#[test]
fn test_metadata_validate_empty_filename() {
    let mut meta = sample_metadata();
    meta.filename = String::new();

    let err = meta.validate().unwrap_err();
    assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
}

#[test]
fn test_metadata_validate_empty_device_wrap() {
    let mut meta = sample_metadata();
    meta.wrapped_dek.device_wrap = Vec::new();

    let err = meta.validate().unwrap_err();
    assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
}

#[test]
fn test_metadata_validate_empty_wrap_algorithm() {
    let mut meta = sample_metadata();
    meta.wrapped_dek.wrap_algorithm = String::new();

    let err = meta.validate().unwrap_err();
    assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
}
