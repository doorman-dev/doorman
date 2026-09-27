use std::env;

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use fernet::Fernet;
use sha2::{Digest, Sha256};

fn cipher() -> Option<Fernet> {
    let key = env::var("TOKEN_ENCRYPTION_KEY")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            env::var("MEM_ENCRYPTION_KEY")
                .ok()
                .filter(|value| !value.is_empty())
        })?;
    Fernet::new(&key).or_else(|| {
        let encoded = URL_SAFE.encode(Sha256::digest(key.as_bytes()));
        Fernet::new(&encoded)
    })
}

pub fn encrypt_value(value: Option<&str>) -> Option<String> {
    let value = value?;
    Some(match cipher() {
        Some(cipher) => format!("enc:{}", cipher.encrypt(value.as_bytes())),
        None => value.to_owned(),
    })
}

pub fn decrypt_value(value: Option<&str>) -> Option<String> {
    let value = value?;
    let Some(token) = value.strip_prefix("enc:") else {
        return Some(value.to_owned());
    };
    let cipher = cipher()?;
    String::from_utf8(cipher.decrypt(token).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_values_pass_through_without_an_encryption_marker() {
        assert_eq!(decrypt_value(Some("plain")), Some("plain".to_owned()));
        assert_eq!(decrypt_value(None), None);
    }
}
