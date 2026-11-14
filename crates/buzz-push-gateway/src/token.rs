//! Endpoint custody: APNs tokens and Web Push subscriptions. Ciphertexts are
//! self-describing and can be decrypted by the current key or bounded
//! decrypt-only predecessors during key rotation.
use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

use crate::authority::Transport;

/// Each transport's custody is bound to it: one can't be opened as the
/// other. A gateway from before Web Push can't open a browser subscription,
/// so it never sends one to APNs as a token.
fn aad_prefix(transport: Transport) -> &'static [u8] {
    match transport {
        Transport::Apns => b"buzz-apns-token-v1:",
        Transport::WebPush => b"buzz-webpush-subscription-v1:",
    }
}
const MAX_KEY_ID_BYTES: usize = 32;
const MAX_CIPHERTEXT_BYTES: usize = 2048;
/// Longest endpoint accepted for custody. Sealed, it stays within
/// [`MAX_CIPHERTEXT_BYTES`] and the store's column bound. Each transport
/// bounds its own endpoints more tightly.
pub const MAX_CUSTODY_BYTES: usize = 1024;

#[derive(Clone)]
pub struct TokenKey {
    id: String,
    cipher: Aes256Gcm,
}
#[derive(Clone)]
pub struct TokenKeyring {
    current: TokenKey,
    predecessors: HashMap<String, TokenKey>,
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("invalid token ciphertext")]
    Invalid,
    #[error("token keyring is empty or contains duplicate ids")]
    InvalidKeyring,
}

impl TokenKey {
    pub fn new(id: impl Into<String>, key: &[u8]) -> Result<Self, TokenError> {
        let id = id.into();
        if id.is_empty()
            || id.len() > MAX_KEY_ID_BYTES
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(TokenError::Invalid);
        }
        Ok(Self {
            id,
            cipher: Aes256Gcm::new_from_slice(key).map_err(|_| TokenError::Invalid)?,
        })
    }
    fn aad(&self, transport: Transport) -> Vec<u8> {
        [aad_prefix(transport), self.id.as_bytes()].concat()
    }
}

impl TokenKeyring {
    pub fn new(keys: Vec<TokenKey>) -> Result<Self, TokenError> {
        let mut keys = keys.into_iter();
        let current = keys.next().ok_or(TokenError::InvalidKeyring)?;
        let rest: Vec<_> = keys.collect();
        let mut ids = HashSet::new();
        if !ids.insert(current.id.clone()) || rest.iter().any(|k| !ids.insert(k.id.clone())) {
            return Err(TokenError::InvalidKeyring);
        }
        Ok(Self {
            current,
            predecessors: rest.into_iter().map(|k| (k.id.clone(), k)).collect(),
        })
    }
    /// Seal `token`, an endpoint of `transport`, with the current key.
    pub fn seal(&self, transport: Transport, token: &[u8]) -> Result<Vec<u8>, TokenError> {
        if token.is_empty() || token.len() > MAX_CUSTODY_BYTES {
            return Err(TokenError::Invalid);
        }
        let mut nonce = [0; 12];
        OsRng.fill_bytes(&mut nonce);
        let mut sealed = nonce.to_vec();
        sealed.extend(
            self.current
                .cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    aes_gcm::aead::Payload {
                        msg: token,
                        aad: &self.current.aad(transport),
                    },
                )
                .map_err(|_| TokenError::Invalid)?,
        );
        let encoded =
            format!("{}.{}", self.current.id, URL_SAFE_NO_PAD.encode(sealed)).into_bytes();
        if encoded.len() > MAX_CIPHERTEXT_BYTES {
            return Err(TokenError::Invalid);
        }
        Ok(encoded)
    }
    /// Open custody sealed for `transport`; custody of another transport
    /// fails.
    pub fn open(&self, transport: Transport, encoded: &[u8]) -> Result<Vec<u8>, TokenError> {
        if encoded.len() > MAX_CIPHERTEXT_BYTES {
            return Err(TokenError::Invalid);
        }
        let encoded = std::str::from_utf8(encoded).map_err(|_| TokenError::Invalid)?;
        let (id, body) = encoded.split_once('.').ok_or(TokenError::Invalid)?;
        let key = if id == self.current.id {
            &self.current
        } else {
            self.predecessors.get(id).ok_or(TokenError::Invalid)?
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| TokenError::Invalid)?;
        if bytes.len() < 13 {
            return Err(TokenError::Invalid);
        }
        key.cipher
            .decrypt(
                Nonce::from_slice(&bytes[..12]),
                aes_gcm::aead::Payload {
                    msg: &bytes[12..],
                    aad: &key.aad(transport),
                },
            )
            .map_err(|_| TokenError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_opens_only_as_the_transport_it_was_sealed_for() {
        let ring = TokenKeyring::new(vec![TokenKey::new("k", &[5; 32]).unwrap()]).unwrap();
        for (sealed_as, other) in [
            (Transport::Apns, Transport::WebPush),
            (Transport::WebPush, Transport::Apns),
        ] {
            let sealed = ring.seal(sealed_as, b"endpoint").unwrap();
            assert_eq!(ring.open(sealed_as, &sealed).unwrap(), b"endpoint");
            // A gateway that predates Web Push opens everything as APNs: a
            // browser subscription must not open for it.
            assert!(ring.open(other, &sealed).is_err());
        }
        assert!(ring
            .seal(Transport::WebPush, &[1; MAX_CUSTODY_BYTES])
            .is_ok());
        assert!(ring
            .seal(Transport::WebPush, &[1; MAX_CUSTODY_BYTES + 1])
            .is_err());
        assert!(ring.seal(Transport::Apns, &[]).is_err());
    }
}
