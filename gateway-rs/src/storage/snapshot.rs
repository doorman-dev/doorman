use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, KeyInit},
};
use base64::Engine as _;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    state::GatewayRuntime,
    storage::runtime::{SharedStorage, StorageError},
};

const MAGIC: &[u8; 4] = b"DMP1";
const INFO: &[u8] = b"doorman-mem-dump-v1";

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("{0}")]
    Storage(#[from] StorageError),
    #[error("MEM_ENCRYPTION_KEY must be set and at least 8 characters")]
    MissingKey,
    #[error("invalid or unsupported memory dump")]
    InvalidDump,
    #[error("memory dump encryption failed")]
    Encryption,
    #[error("memory dump path must stay within the configured dump directory")]
    InvalidPath,
    #[error("memory dump I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("memory dump JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u8,
    created_at: String,
    sanitized: bool,
    note: String,
    data: HashMap<String, Vec<Value>>,
}

/// An enabled worker dumps immediately at startup and after a settings update,
/// then waits for the configured cadence. Disabled autosave remains opt-in.
pub fn spawn_autosave(
    storage: std::sync::Arc<SharedStorage>,
    runtime: std::sync::Arc<GatewayRuntime>,
) -> tokio::task::JoinHandle<()> {
    let mut updates = runtime.memory_autosave_config();
    tokio::spawn(async move {
        loop {
            let config = updates.borrow_and_update().clone();
            if !config.enabled {
                if updates.changed().await.is_err() {
                    break;
                }
                continue;
            }
            match dump(&storage, config.dump_path.as_deref()).await {
                Ok(path) => {
                    runtime
                        .memory_snapshot_healthy
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!(path = %path.display(), "memory autosave completed");
                }
                Err(error) => {
                    runtime
                        .memory_snapshot_healthy
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    tracing::error!(%error, "memory autosave failed");
                }
            }
            tokio::select! {
                changed = updates.changed() => { if changed.is_err() { break; } }
                _ = tokio::time::sleep(std::time::Duration::from_secs(config.frequency_seconds.max(60))) => {}
            }
        }
    })
}

pub async fn dump(
    storage: &SharedStorage,
    path_hint: Option<&str>,
) -> Result<PathBuf, SnapshotError> {
    let key_material = encryption_key()?;
    dump_with_key(storage, path_hint, &key_material).await
}

async fn dump_with_key(
    storage: &SharedStorage,
    path_hint: Option<&str>,
    key_material: &str,
) -> Result<PathBuf, SnapshotError> {
    validate_key(key_material)?;
    let data = storage.dump_memory_data().await?;
    let payload = Snapshot {
        version: 1,
        created_at: timestamp_iso(),
        sanitized: false,
        note: "Contains sensitive data; encrypted at rest with MEM_ENCRYPTION_KEY".to_owned(),
        data,
    };
    let plaintext = serde_json::to_vec(&payload)?;
    let blob = encrypt_blob(&plaintext, key_material)?;

    let path = timestamped_path(path_hint)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, blob)?;
    fs::rename(&temporary, &path)?;
    Ok(path)
}

fn encrypt_blob(plaintext: &[u8], key_material: &str) -> Result<Vec<u8>, SnapshotError> {
    validate_key(key_material)?;
    let salt = Uuid::new_v4().into_bytes();
    let key = derive_key(key_material, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| SnapshotError::Encryption)?;
    let nonce = Nonce::generate();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| SnapshotError::Encryption)?;
    let mut blob = Vec::with_capacity(32 + ciphertext.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Restore exactly the requested file, matching Python's management endpoint.
pub async fn restore(
    storage: &SharedStorage,
    path_hint: Option<&str>,
) -> Result<(u8, String), SnapshotError> {
    let key_material = encryption_key()?;
    restore_file_with_key(storage, &request_path(path_hint)?, &key_material).await
}

/// Startup, unlike an explicit restore request, searches for the latest dump.
pub async fn restore_latest(
    storage: &SharedStorage,
    path_hint: Option<&str>,
) -> Result<(u8, String), SnapshotError> {
    let key_material = encryption_key()?;
    let path = resolve_restore_path(path_hint)?.ok_or_else(|| {
        SnapshotError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Dump file not found",
        ))
    })?;
    restore_file_with_key(storage, &path, &key_material).await
}

async fn restore_file_with_key(
    storage: &SharedStorage,
    path: &Path,
    key_material: &str,
) -> Result<(u8, String), SnapshotError> {
    validate_key(key_material)?;
    let blob = fs::read(path)?;
    let mut payload = decrypt_blob(&blob, key_material)?;
    let version = payload.version;
    let created_at = payload.created_at.clone();
    for records in payload.data.values_mut() {
        for record in records {
            restore_python_json_values(record);
        }
    }
    storage.restore_memory_data(payload.data).await?;
    reconcile_bootstrap_admin(storage).await;
    Ok((version, created_at))
}

fn restore_python_json_values(value: &mut Value) {
    match value {
        Value::Object(object)
            if object.get("__type__").and_then(Value::as_str) == Some("bytes") =>
        {
            let decoded = object
                .get("data")
                .and_then(Value::as_str)
                .and_then(|encoded| {
                    base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .ok()
                })
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_default();
            *value = Value::String(decoded);
        }
        Value::Object(object) => {
            for value in object.values_mut() {
                restore_python_json_values(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                restore_python_json_values(value);
            }
        }
        _ => {}
    }
}

async fn reconcile_bootstrap_admin(storage: &SharedStorage) {
    let Ok(Some(admin)) = storage
        .find_one("users", &serde_json::json!({"username": "admin"}))
        .await
    else {
        return;
    };
    let mut updates = serde_json::Map::new();
    if let Ok(email) = env::var("DOORMAN_ADMIN_EMAIL")
        && admin.get("email").and_then(Value::as_str) != Some(email.as_str())
    {
        updates.insert("email".to_owned(), Value::String(email));
    }
    if admin.get("ui_access").and_then(Value::as_bool) != Some(true) {
        updates.insert("ui_access".to_owned(), Value::Bool(true));
    }
    if let Ok(password) = env::var("DOORMAN_ADMIN_PASSWORD")
        && let Ok(password) = bcrypt::hash(password, bcrypt::DEFAULT_COST)
    {
        updates.insert("password".to_owned(), Value::String(password));
    }
    if !updates.is_empty() {
        let _ = storage
            .update_one(
                "users",
                &serde_json::json!({"username": "admin"}),
                &Value::Object(updates),
            )
            .await;
    }
}

fn decrypt_blob(blob: &[u8], key_material: &str) -> Result<Snapshot, SnapshotError> {
    let plaintext = decrypt_plaintext(blob, key_material)?;
    let snapshot: Snapshot = serde_json::from_slice(&plaintext)?;
    if snapshot.version != 1 {
        return Err(SnapshotError::InvalidDump);
    }
    Ok(snapshot)
}

fn decrypt_plaintext(blob: &[u8], key_material: &str) -> Result<Vec<u8>, SnapshotError> {
    validate_key(key_material)?;
    if blob.len() < 32 || &blob[..4] != MAGIC {
        return Err(SnapshotError::InvalidDump);
    }
    let salt: [u8; 16] = blob[4..20]
        .try_into()
        .map_err(|_| SnapshotError::InvalidDump)?;
    let nonce = Nonce::try_from(&blob[20..32]).map_err(|_| SnapshotError::InvalidDump)?;
    let key = derive_key(key_material, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| SnapshotError::Encryption)?;
    cipher
        .decrypt(&nonce, &blob[32..])
        .map_err(|_| SnapshotError::InvalidDump)
}

fn derive_key(key_material: &str, salt: &[u8]) -> Result<[u8; 32], SnapshotError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), key_material.as_bytes());
    // `expand` fills every byte before this key is used. Keeping the buffer
    // default-initialized avoids implying that a fixed key is in use.
    let mut key: [u8; 32] = Default::default();
    hkdf.expand(INFO, &mut key)
        .map_err(|_| SnapshotError::Encryption)?;
    Ok(key)
}

fn encryption_key() -> Result<String, SnapshotError> {
    let key = env::var("MEM_ENCRYPTION_KEY").map_err(|_| SnapshotError::MissingKey)?;
    validate_key(&key)?;
    Ok(key)
}

fn validate_key(key: &str) -> Result<(), SnapshotError> {
    // Python's len(str) counts characters, not UTF-8 bytes.
    if key.chars().count() < 8 {
        return Err(SnapshotError::MissingKey);
    }
    Ok(())
}

fn default_path() -> PathBuf {
    env::var("MEM_DUMP_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("generated/memory_dump.bin"))
}

fn request_path(path_hint: Option<&str>) -> Result<PathBuf, SnapshotError> {
    // `dump_path` is an administrator-controlled setting.  The Python
    // baseline accepts both absolute paths and nested paths relative to the
    // service working directory; restricting it to a filename made the
    // persisted default (`generated/memory_dump.bin`) unusable by autosave.
    // The management routes require `manage_security`, so retain that access
    // boundary here rather than silently changing the configured destination.
    Ok(path_hint
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_path))
}

fn timestamped_path(path_hint: Option<&str>) -> Result<PathBuf, SnapshotError> {
    let hint = request_path(path_hint)?;
    let (directory, stem) = directory_and_stem(&hint);
    Ok(directory.join(format!("{stem}-{}.bin", timestamp_compact())))
}

fn directory_and_stem(hint: &Path) -> (PathBuf, String) {
    if hint.is_dir() || hint.as_os_str().to_string_lossy().ends_with('/') {
        (hint.to_path_buf(), "memory_dump".to_owned())
    } else {
        (
            hint.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
            hint.file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("memory_dump")
                .to_owned(),
        )
    }
}

fn resolve_restore_path(path_hint: Option<&str>) -> Result<Option<PathBuf>, SnapshotError> {
    Ok(find_latest_dump(
        path_hint
            .filter(|value| !value.trim().is_empty())
            .map(Path::new),
        &default_path(),
    ))
}

fn find_latest_dump(path_hint: Option<&Path>, configured_default: &Path) -> Option<PathBuf> {
    let (directory, stem) = directory_and_stem(path_hint.unwrap_or(configured_default));
    if let Some(path) = newest_bin(&directory, Some(&stem)) {
        return Some(path);
    }
    let (directory, stem) = directory_and_stem(configured_default);
    newest_bin(&directory, Some(&stem)).or_else(|| newest_bin(&directory, None))
}

fn newest_bin(directory: &Path, stem: Option<&str>) -> Option<PathBuf> {
    let mut files = fs::read_dir(directory)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
                && name.to_ascii_lowercase().ends_with(".bin")
                && stem.is_none_or(|stem| name.starts_with(&format!("{stem}-")))
        })
        .collect::<Vec<_>>();
    files.sort_by_key(|entry| entry.metadata().and_then(|meta| meta.modified()).ok());
    files.pop().map(|entry| entry.path())
}

fn timestamp_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn timestamp_compact() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = env::temp_dir().join(format!("doorman-snapshot-test-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str, modified: u64) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, b"fixture").unwrap();
            fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(
                    fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(modified)),
                )
                .unwrap();
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn test_storage() -> SharedStorage {
        SharedStorage::connect(&crate::config::SharedStorageConfig::default())
            .await
            .unwrap()
    }

    #[test]
    fn filename_only_dump_hint_uses_current_directory() {
        assert_eq!(
            directory_and_stem(Path::new("backup.bin")),
            (PathBuf::from("."), "backup".to_owned())
        );
    }

    #[tokio::test]
    async fn dump_file_naming_and_directory_creation_match_python() {
        let directory = TestDirectory::new();
        let hint = directory.0.join("custom/mydump.bin");
        let path = dump_with_key(&test_storage().await, hint.to_str(), "snapshot-test-key")
            .await
            .unwrap();
        assert!(path.is_file());
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("mydump-"));
        assert!(name.ends_with(".bin"));
        assert_eq!(find_latest_dump(Some(&hint), &hint), Some(path));
    }

    #[tokio::test]
    async fn dump_directory_hint_uses_python_default_stem() {
        let directory = TestDirectory::new();
        let path = dump_with_key(
            &test_storage().await,
            directory.0.to_str(),
            "snapshot-test-key",
        )
        .await
        .unwrap();
        assert!(path.is_file());
        assert!(
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("memory_dump-")
        );
        assert_eq!(
            find_latest_dump(Some(&directory.0), &directory.0.join("fallback.bin")),
            Some(path)
        );
    }

    #[test]
    fn find_latest_prefers_newest_matching_stem_by_modification_time() {
        let directory = TestDirectory::new();
        directory.file("memory_dump-20200101T000000Z.bin", 100);
        let newest = directory.file("memory_dump-20300101T000000Z.bin", 200);
        directory.file("otherstem-20990101T000000Z.bin", 400);
        // Filenames alone must not override actual modification time.
        directory.file("memory_dump-20990101T000000Z.bin", 50);
        let hint = directory.0.join("memory_dump.bin");
        assert_eq!(find_latest_dump(Some(&hint), &hint), Some(newest));
    }

    #[test]
    fn find_latest_directory_hint_ignores_other_stems_with_or_without_slash() {
        let directory = TestDirectory::new();
        let expected = directory.file("memory_dump-20220101T000000Z.bin", 100);
        directory.file("otherstem-20990101T000000Z.bin", 200);
        let default = directory.0.join("fallback.bin");
        for hint in [
            directory.0.clone(),
            PathBuf::from(format!("{}/", directory.0.display())),
        ] {
            assert_eq!(
                find_latest_dump(Some(&hint), &default),
                Some(expected.clone())
            );
        }
    }

    #[test]
    fn find_latest_uses_default_when_no_hint() {
        let directory = TestDirectory::new();
        directory.file("memory_dump-20000101T000000Z.bin", 100);
        let expected = directory.file("memory_dump-20500101T000000Z.bin", 200);
        assert_eq!(
            find_latest_dump(None, &directory.0.join("memory_dump.bin")),
            Some(expected)
        );
    }

    #[test]
    fn find_latest_falls_back_to_default_stem_then_any_bin_matching_python() {
        let directory = TestDirectory::new();
        let other = directory.file("other-20500101T000000Z.BIN", 300);
        let expected = directory.file("memory_dump-20200101T000000Z.bin", 100);
        let hint = directory.0.join("missing/custom.bin");
        assert_eq!(
            find_latest_dump(Some(&hint), &directory.0.join("memory_dump.bin")),
            Some(expected)
        );
        assert_eq!(
            find_latest_dump(Some(&hint), &directory.0.join("unknown.bin")),
            Some(other)
        );
    }

    #[test]
    fn encrypt_decrypt_roundtrip_matches_python() {
        let key = Uuid::new_v4().to_string();
        let plaintext = b"hello world";
        let blob = encrypt_blob(plaintext, &key).unwrap();
        assert!(blob.starts_with(b"DMP1"));
        assert_eq!(decrypt_plaintext(&blob, &key).unwrap(), plaintext);
        // Fresh salt and nonce prevent identical dumps from reusing ciphertext.
        assert_ne!(encrypt_blob(plaintext, &key).unwrap(), blob);
    }

    #[test]
    fn encryption_requires_eight_characters_like_python() {
        for key in ["", "short", "éééé"] {
            assert!(matches!(
                encrypt_blob(b"data", key),
                Err(SnapshotError::MissingKey)
            ));
        }
        let key = "éééééééé";
        let blob = encrypt_blob(b"data", key).unwrap();
        assert_eq!(decrypt_plaintext(&blob, key).unwrap(), b"data");
    }

    #[tokio::test]
    async fn dump_rejects_short_key_without_creating_a_file() {
        let directory = TestDirectory::new();
        let hint = directory.0.join("nested/dump.bin");
        assert!(matches!(
            dump_with_key(&test_storage().await, hint.to_str(), "short").await,
            Err(SnapshotError::MissingKey)
        ));
        assert!(!directory.0.join("nested").exists());
    }

    #[tokio::test]
    async fn restore_nonexistent_file_does_not_fall_back_or_mutate_data() {
        let directory = TestDirectory::new();
        let storage = test_storage().await;
        let hint = directory.0.join("memory_dump.bin");
        dump_with_key(&storage, hint.to_str(), "snapshot-test-key")
            .await
            .unwrap();
        storage
            .insert_one(
                "settings",
                serde_json::json!({"marker": "keep-current-state"}),
            )
            .await
            .unwrap();
        let before = storage.dump_memory_data().await.unwrap();
        assert!(find_latest_dump(Some(&hint), &hint).is_some());
        assert!(matches!(
            restore_file_with_key(&storage, &hint, "snapshot-test-key").await,
            Err(SnapshotError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound
        ));
        assert_eq!(storage.dump_memory_data().await.unwrap(), before);
    }

    #[tokio::test]
    async fn failed_restore_is_atomic_and_exact_file_restore_succeeds() {
        let directory = TestDirectory::new();
        let storage = test_storage().await;
        storage
            .insert_one(
                "users",
                serde_json::json!({"username": "tmp", "email": "t@t.t", "password": "x"}),
            )
            .await
            .unwrap();
        let original = storage.dump_memory_data().await.unwrap();
        let path = dump_with_key(&storage, directory.0.to_str(), "snapshot-test-key")
            .await
            .unwrap();
        assert_eq!(
            find_latest_dump(Some(&directory.0), &directory.0.join("memory_dump.bin")),
            Some(path.clone())
        );
        storage
            .replace_collection("users", Vec::new())
            .await
            .unwrap();
        assert!(
            storage
                .find_many("users", &serde_json::json!({}))
                .await
                .unwrap()
                .is_empty()
        );
        storage
            .insert_one("settings", serde_json::json!({"marker": "new-state"}))
            .await
            .unwrap();
        let before = storage.dump_memory_data().await.unwrap();
        assert!(
            restore_file_with_key(&storage, &path, "wrong-snapshot-key")
                .await
                .is_err()
        );
        assert_eq!(storage.dump_memory_data().await.unwrap(), before);
        let bytes = fs::read(&path).unwrap();
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        fs::write(&path, tampered).unwrap();
        assert!(
            restore_file_with_key(&storage, &path, "snapshot-test-key")
                .await
                .is_err()
        );
        assert_eq!(storage.dump_memory_data().await.unwrap(), before);
        fs::write(&path, bytes).unwrap();
        let (version, _) = restore_file_with_key(&storage, &path, "snapshot-test-key")
            .await
            .unwrap();
        assert_eq!(version, 1);
        assert_eq!(storage.dump_memory_data().await.unwrap(), original);
    }

    #[test]
    fn derives_the_python_compatible_key() {
        let key_material = Uuid::new_v4().to_string();
        let salt = Uuid::new_v4().into_bytes();
        let key = derive_key(&key_material, &salt).unwrap();
        assert_eq!(key.len(), 32);
        assert_ne!(key, [0; 32]);
    }

    #[test]
    fn accepts_configured_snapshot_paths_matching_the_python_baseline() {
        assert_eq!(
            request_path(Some("backup.bin")).unwrap(),
            PathBuf::from("backup.bin")
        );
        assert_eq!(
            request_path(Some("nested/backup.bin")).unwrap(),
            PathBuf::from("nested/backup.bin")
        );
        assert_eq!(
            request_path(Some("/tmp/backup.bin")).unwrap(),
            PathBuf::from("/tmp/backup.bin")
        );
        assert_eq!(request_path(Some(" ")).unwrap(), default_path());
    }

    #[test]
    fn decrypts_a_dump_created_by_the_python_backend() {
        use base64::Engine;

        let encoded = "RE1QMTAxMjM0NTY3ODlhYmNkZWZweXRob24tbm9uY2URWpMrOX++JWrZPCQ7vDZiPavCE/HhK9eZ94o5vRr7RV+fhZvWcjeN73XBh9VVn4lq7ftjeo+Uk7mCqZslCCpIyy4iutNThunPlKSvNhgfGc3czermqttHTWXW5Pvcjj+2sry/bfSUM6OQF1Z1JK4Faplxy0Bm/DOk11zJwPDY2PmGjDiUa23GixnceU17sdtVYSqY47N1+4/zy3EcWur4npCcP5HwJu1x7Fokz0xPImtWxMbf1l0Un6VyThjUJ0W1KP/YgvFb927zX8JJctVwlSLzRaFtZfzpoF5EPnZJ9FnALQl7PsYddN0V";
        let blob = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let snapshot = decrypt_blob(&blob, "fixture-key").unwrap();

        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.created_at, "2026-08-06T12:34:56Z");
        assert_eq!(snapshot.data["users"][0]["username"], "fixture-admin");
        assert_eq!(snapshot.data["users"][0]["password"], "hash");
    }

    #[test]
    fn restores_python_byte_wrappers_for_password_hashes() {
        let mut value = serde_json::json!({
            "password": {"__type__": "bytes", "data": "JDJiJDEyJGhhc2g="},
            "nested": [{"value": {"__type__": "bytes", "data": "dGV4dA=="}}]
        });
        restore_python_json_values(&mut value);
        assert_eq!(value["password"], "$2b$12$hash");
        assert_eq!(value["nested"][0]["value"], "text");
    }

    #[test]
    fn rejects_unsupported_snapshot_version() {
        let payload = Snapshot {
            version: 2,
            created_at: "2026-08-06T12:34:56Z".to_owned(),
            sanitized: false,
            note: "unsupported fixture".to_owned(),
            data: HashMap::new(),
        };
        let plaintext = serde_json::to_vec(&payload).unwrap();
        let salt = Uuid::new_v4().into_bytes();
        let key = derive_key("fixture-key", &salt).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&Uuid::new_v4().into_bytes()[..12]);
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);

        assert!(matches!(
            decrypt_blob(&blob, "fixture-key"),
            Err(SnapshotError::InvalidDump)
        ));
    }
}
