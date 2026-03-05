use secure_core::error::SecureCoreError;
use secure_core::metadata::{
    DocumentMetadata, WrapsEnvelope, WRAPS_SCHEMA_VERSION,
};

fn sample_envelope() -> WrapsEnvelope {
    WrapsEnvelope::new_device(
        "AES-256-GCM-KEYSTORE".into(),
        "secure_core_master_key_v1".into(),
        vec![0xA0; 12],
        vec![0xB0; 16],
        vec![0x01, 0x02, 0x03, 0x04],
    )
}

fn sample_metadata() -> DocumentMetadata {
    DocumentMetadata {
        doc_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        filename: "photo.jpg".into(),
        mime_type: Some("image/jpeg".into()),
        created_at: 1709654400,
        plaintext_size: Some(102400),
        ciphertext_size: 102816,
        content_hash: Some([0xAB; 32]),
        wrapped_dek: sample_envelope(),
    }
}

// ── WrapsEnvelope validation ──────────────────────────────────────────

#[test]
fn test_wraps_envelope_valid() {
    let env = sample_envelope();
    assert!(env.validate().is_ok());
}

#[test]
fn test_wraps_envelope_null_device_rejected() {
    let env = WrapsEnvelope {
        schema_version: WRAPS_SCHEMA_VERSION.to_string(),
        device: None,
        recovery: None,
    };
    let err = env.validate().unwrap_err();
    assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
    assert!(format!("{err}").contains("device"));
}

#[test]
fn test_wraps_envelope_unknown_schema_version_rejected() {
    let mut env = sample_envelope();
    env.schema_version = "99.0".to_string();
    let err = env.validate().unwrap_err();
    assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
    assert!(format!("{err}").contains("schema_version"));
}

#[test]
fn test_wraps_envelope_recovery_null_accepted() {
    let mut env = sample_envelope();
    env.recovery = None;
    assert!(env.validate().is_ok());
}

#[test]
fn test_wraps_envelope_recovery_non_null_accepted_v1() {
    // In V1, recovery non-null is tolerated (warning, not error)
    let mut env = sample_envelope();
    env.recovery = Some(serde_json::json!({"placeholder": true}));
    // Should still validate OK — recovery is ignored in V1
    assert!(env.validate().is_ok());
}

#[test]
fn test_wraps_envelope_empty_algo_rejected() {
    let env = WrapsEnvelope::new_device(
        String::new(),
        "alias".into(),
        vec![0; 12],
        vec![0; 16],
        vec![1],
    );
    let err = env.validate().unwrap_err();
    assert!(format!("{err}").contains("algo"));
}

#[test]
fn test_wraps_envelope_empty_key_alias_rejected() {
    let env = WrapsEnvelope::new_device(
        "AES-256-GCM-KEYSTORE".into(),
        String::new(),
        vec![0; 12],
        vec![0; 16],
        vec![1],
    );
    let err = env.validate().unwrap_err();
    assert!(format!("{err}").contains("key_alias"));
}

#[test]
fn test_wraps_envelope_wrong_iv_length_rejected() {
    let env = WrapsEnvelope::new_device(
        "AES-256-GCM-KEYSTORE".into(),
        "alias".into(),
        vec![0; 8], // wrong: should be 12
        vec![0; 16],
        vec![1],
    );
    let err = env.validate().unwrap_err();
    assert!(format!("{err}").contains("iv"));
}

#[test]
fn test_wraps_envelope_wrong_tag_length_rejected() {
    let env = WrapsEnvelope::new_device(
        "AES-256-GCM-KEYSTORE".into(),
        "alias".into(),
        vec![0; 12],
        vec![0; 8], // wrong: should be 16
        vec![1],
    );
    let err = env.validate().unwrap_err();
    assert!(format!("{err}").contains("tag"));
}

#[test]
fn test_wraps_envelope_empty_ciphertext_rejected() {
    let env = WrapsEnvelope::new_device(
        "AES-256-GCM-KEYSTORE".into(),
        "alias".into(),
        vec![0; 12],
        vec![0; 16],
        vec![], // empty
    );
    let err = env.validate().unwrap_err();
    assert!(format!("{err}").contains("ciphertext"));
}

// ── Serialization ─────────────────────────────────────────────────────

#[test]
fn test_wraps_envelope_json_roundtrip() {
    let env = sample_envelope();
    let json = serde_json::to_string_pretty(&env).unwrap();
    let parsed: WrapsEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, parsed);
}

#[test]
fn test_wraps_envelope_json_fields_present() {
    let env = sample_envelope();
    let json = serde_json::to_string(&env).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"device\""));
    assert!(json.contains("\"algo\""));
    assert!(json.contains("\"key_alias\""));
    assert!(json.contains("\"iv\""));
    assert!(json.contains("\"tag\""));
    assert!(json.contains("\"ciphertext\""));
}

#[test]
fn test_wraps_envelope_base64_encoding() {
    let env = sample_envelope();
    let device = env.device.as_ref().unwrap();
    // Verify the base64 values decode correctly
    let iv = device.iv_bytes().unwrap();
    assert_eq!(iv.len(), 12);
    assert_eq!(iv, vec![0xA0; 12]);

    let tag = device.tag_bytes().unwrap();
    assert_eq!(tag.len(), 16);
    assert_eq!(tag, vec![0xB0; 16]);

    let ct = device.ciphertext_bytes().unwrap();
    assert_eq!(ct, vec![0x01, 0x02, 0x03, 0x04]);
}

// ── DocumentMetadata ──────────────────────────────────────────────────

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
    assert!(json.contains("\"schema_version\""));
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
        wrapped_dek: sample_envelope(),
    };

    let json = serde_json::to_string(&meta).unwrap();
    assert!(!json.contains("\"mime_type\""));
    assert!(!json.contains("\"plaintext_size\""));
    assert!(!json.contains("\"content_hash\""));

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
fn test_metadata_validate_null_device_wrap() {
    let mut meta = sample_metadata();
    meta.wrapped_dek.device = None;

    let err = meta.validate().unwrap_err();
    assert!(matches!(err, SecureCoreError::InvalidParameter(_)));
}
