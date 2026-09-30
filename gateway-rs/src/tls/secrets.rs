use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TlsSecretError {
    #[error("TLS_SECRET_ENCRYPTION_KEY must be base64 for exactly 32 random bytes")]
    MissingKey,
    #[error("TLS secret encryption failed")]
    Encryption,
    #[error("TLS secret decryption failed")]
    Decryption,
}

fn cipher() -> Result<Aes256Gcm, TlsSecretError> {
    let raw = std::env::var("TLS_SECRET_ENCRYPTION_KEY").map_err(|_| TlsSecretError::MissingKey)?;
    let key = STANDARD
        .decode(raw)
        .map_err(|_| TlsSecretError::MissingKey)?;
    if key.len() != 32 {
        return Err(TlsSecretError::MissingKey);
    }
    Aes256Gcm::new_from_slice(&key).map_err(|_| TlsSecretError::MissingKey)
}

pub fn seal(id: &str, field: &str, plaintext: &[u8]) -> Result<String, TlsSecretError> {
    let cipher = cipher()?;
    let nonce: [u8; 12] = rand::random();
    let aad = format!("{id}:{field}");
    let nonce_array = Nonce::try_from(nonce.as_slice()).map_err(|_| TlsSecretError::Encryption)?;
    let ciphertext = cipher
        .encrypt(
            &nonce_array,
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| TlsSecretError::Encryption)?;
    let mut blob = Vec::with_capacity(nonce.len() + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(format!("v1:{}", STANDARD.encode(blob)))
}

pub fn open(id: &str, field: &str, sealed: &str) -> Result<Vec<u8>, TlsSecretError> {
    let value = sealed
        .strip_prefix("v1:")
        .ok_or(TlsSecretError::Decryption)?;
    let blob = STANDARD
        .decode(value)
        .map_err(|_| TlsSecretError::Decryption)?;
    if blob.len() < 28 {
        return Err(TlsSecretError::Decryption);
    }
    let aad = format!("{id}:{field}");
    let nonce_array = Nonce::try_from(&blob[..12]).map_err(|_| TlsSecretError::Decryption)?;
    cipher()?
        .decrypt(
            &nonce_array,
            Payload {
                msg: &blob[12..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| TlsSecretError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_an_explicit_secret_key() {
        if std::env::var_os("TLS_SECRET_ENCRYPTION_KEY").is_none() {
            assert!(matches!(
                seal("profile", "key", b"private"),
                Err(TlsSecretError::MissingKey)
            ));
        }
    }
}
