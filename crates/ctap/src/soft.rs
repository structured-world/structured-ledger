//! Software [`Crypto`] on the RustCrypto crates, for host tests and fuzzing.
//!
//! Its random numbers are SHA-256 in counter mode over a seed, so runs are reproducible; it is
//! never a substitute for the device's TRNG.

use core::fmt;

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{DerSignature, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{Crypto, CryptoError, KEY_LEN, NONCE_LEN, PUBLIC_KEY_LEN, Signature, TAG_LEN};

/// Software cryptography with a fixed application node and a seeded generator. Its `Debug`
/// output never prints the node or the seed, and both are zeroized on drop.
pub struct SoftCrypto {
    node: [u8; KEY_LEN],
    seed: [u8; KEY_LEN],
    counter: u64,
}

impl Drop for SoftCrypto {
    fn drop(&mut self) {
        self.node.zeroize();
        self.seed.zeroize();
    }
}

impl fmt::Debug for SoftCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftCrypto")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl SoftCrypto {
    /// A platform whose BIP32 application node is `node` and whose random stream comes from
    /// `seed`.
    pub const fn new(node: [u8; KEY_LEN], seed: [u8; KEY_LEN]) -> Self {
        Self {
            node,
            seed,
            counter: 0,
        }
    }
}

impl Crypto for SoftCrypto {
    fn random(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(KEY_LEN) {
            let block = self.sha256(&[&self.seed, &self.counter.to_be_bytes()]);
            chunk.copy_from_slice(&block[..chunk.len()]);
            self.counter = self
                .counter
                .checked_add(1)
                .expect("a test never draws 2^64 blocks");
        }
    }

    fn sha256(&self, parts: &[&[u8]]) -> [u8; KEY_LEN] {
        let mut hash = Sha256::new();
        for part in parts {
            hash.update(part);
        }
        hash.finalize().into()
    }

    fn hmac_sha256(&self, key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; KEY_LEN]> {
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes keys of any length");
        for part in parts {
            mac.update(part);
        }
        Zeroizing::new(mac.finalize().into_bytes().into())
    }

    fn aes256_gcm_seal(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
    ) -> [u8; TAG_LEN] {
        // Borrowed, not copied: a temporary key array would stay on the stack unzeroized.
        let cipher = Aes256Gcm::new(key.into());
        cipher
            .encrypt_inout_detached(&Nonce::from(*nonce), aad, data.into())
            .expect("AES-GCM takes messages far longer than a credential ID")
            .into()
    }

    fn aes256_gcm_open(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), CryptoError> {
        let cipher = Aes256Gcm::new(key.into());
        cipher
            .decrypt_inout_detached(&Nonce::from(*nonce), aad, data.into(), &Tag::from(*tag))
            .map_err(|_| CryptoError::Authentication)
    }

    fn p256_public_key(
        &self,
        private_key: &[u8; KEY_LEN],
    ) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError> {
        let key = SigningKey::from_slice(private_key).map_err(|_| CryptoError::InvalidKey)?;
        let point = key.verifying_key().to_sec1_point(false);
        point
            .as_bytes()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)
    }

    fn p256_sign(
        &mut self,
        private_key: &[u8; KEY_LEN],
        digest: &[u8; KEY_LEN],
    ) -> Result<Signature, CryptoError> {
        let key = SigningKey::from_slice(private_key).map_err(|_| CryptoError::InvalidKey)?;
        let signature: DerSignature = key
            .sign_prehash(digest)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Signature::from_der(signature.as_bytes()).expect("a P-256 DER signature fits"))
    }

    fn application_node(&mut self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.node)
    }
}
