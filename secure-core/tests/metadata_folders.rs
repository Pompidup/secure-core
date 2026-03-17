use secure_core::metadata::{DocumentMetadata, FolderMetadata, WrapsEnvelope};

fn sample_envelope() -> WrapsEnvelope {
    WrapsEnvelope::new_device(
        "AES-256-GCM-KEYSTORE".into(),
        "secure_core_master_key_v1".into(),
        vec![0xA0; 12],
        vec![0xB0; 16],
        vec![0x01, 0x02, 0x03, 0x04],
    )
}

fn sample_folder() -> FolderMetadata {
    FolderMetadata {
        id: "f47ac10b-58cc-4372-a567-0e02b2c3d479".into(),
        name: "Finance".into(),
        created_at: 1709654400000,
        updated_at: 1709654400000,
    }
}

fn sample_metadata_with_folder() -> DocumentMetadata {
    DocumentMetadata {
        doc_id: "550e8400-e29b-41d4-a716-446655440000".into(),
        filename: "photo.jpg".into(),
        mime_type: Some("image/jpeg".into()),
        created_at: 1709654400,
        plaintext_size: Some(102400),
        ciphertext_size: 102816,
        content_hash: Some([0xAB; 32]),
        tags: None,
        folder_id: Some("f47ac10b-58cc-4372-a567-0e02b2c3d479".into()),
        wrapped_dek: sample_envelope(),
    }
}

// ── FolderMetadata tests ─────────────────────────────────────────────

#[test]
fn test_folder_metadata_roundtrip() {
    let folder = sample_folder();
    let json = serde_json::to_string_pretty(&folder).unwrap();
    let parsed: FolderMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(folder, parsed);
}

#[test]
fn test_folder_metadata_json_fields() {
    let folder = sample_folder();
    let json = serde_json::to_string(&folder).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"name\""));
    assert!(json.contains("\"created_at\""));
    assert!(json.contains("\"updated_at\""));
}

// ── DocumentMetadata folder_id tests ─────────────────────────────────

#[test]
fn test_document_metadata_folder_id_none_omitted() {
    let meta = DocumentMetadata {
        doc_id: "abc-123".into(),
        filename: "doc.pdf".into(),
        mime_type: None,
        created_at: 1709654400,
        plaintext_size: None,
        ciphertext_size: 500,
        content_hash: None,
        tags: None,
        folder_id: None,
        wrapped_dek: sample_envelope(),
    };
    let json = serde_json::to_string(&meta).unwrap();
    assert!(!json.contains("\"folder_id\""));
}

#[test]
fn test_document_metadata_folder_id_some_present() {
    let meta = sample_metadata_with_folder();
    let json = serde_json::to_string(&meta).unwrap();
    assert!(json.contains("\"folder_id\""));
    assert!(json.contains("f47ac10b-58cc-4372-a567-0e02b2c3d479"));
}

#[test]
fn test_document_metadata_v1_compat_no_folder_id() {
    // JSON without folder_id key — simulates pre-folder data
    let json = r#"{
        "doc_id": "abc-123",
        "filename": "doc.pdf",
        "created_at": 1709654400,
        "ciphertext_size": 500,
        "wrapped_dek": {
            "schema_version": "1.1",
            "device": {
                "algo": "AES-256-GCM-KEYSTORE",
                "key_alias": "secure_core_master_key_v1",
                "iv": "oKCgoKCgoKCgoKCg",
                "tag": "sLCwsLCwsLCwsLCwsLCw",
                "ciphertext": "AQIDBA=="
            },
            "recovery": null
        }
    }"#;
    let meta: DocumentMetadata = serde_json::from_str(json).unwrap();
    assert_eq!(meta.folder_id, None);
}

#[test]
fn test_document_metadata_folder_id_roundtrip() {
    let meta = sample_metadata_with_folder();
    let json = serde_json::to_string_pretty(&meta).unwrap();
    let parsed: DocumentMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(meta, parsed);
    assert_eq!(
        parsed.folder_id,
        Some("f47ac10b-58cc-4372-a567-0e02b2c3d479".into())
    );
}
