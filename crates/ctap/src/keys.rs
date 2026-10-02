//! Key hierarchy below the application's BIP32 node: the root key, the credential wrapping key
//! and seed-recoverable credential keys.
//!
//! Every key lives in a [`Zeroizing`] buffer for the duration of one command.

use zeroize::Zeroizing;

use crate::crypto::{Crypto, CryptoError, KEY_LEN, hkdf_sha256, is_p256_private_key};

/// Hardened BIP32 index bit.
const HARDENED: u32 = 0x8000_0000;

/// The application path `m/5722689'/5262163'/21328'/0'`: the first two levels are the path the
/// Ledger Security Key application declares, `21328'` (`0x5350`, "SP") separates this
/// application's keys.
pub const APPLICATION_PATH: [u32; 4] = [
    5_722_689 | HARDENED,
    5_262_163 | HARDENED,
    21_328 | HARDENED,
    HARDENED,
];

/// Salt of the root key, naming this application and the version of the hierarchy.
const ROOT_SALT: &[u8] = b"structured-passkeys/v1";

/// The root key `K_root = HKDF-SHA-256(ikm = node, salt = "structured-passkeys/v1", info =
/// "root")`, from which the purpose keys are derived when needed.
pub struct KeyRing {
    root: Zeroizing<[u8; KEY_LEN]>,
}

impl core::fmt::Debug for KeyRing {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KeyRing")
    }
}

impl KeyRing {
    /// Derives the root key from the application node.
    pub fn new<C: Crypto>(crypto: &mut C) -> Self {
        let node = crypto.application_node();
        Self {
            root: hkdf_sha256(crypto, ROOT_SALT, &node[..], b"root", &[]),
        }
    }

    /// `K_wrap`, the AES-256-GCM key of credential IDs.
    pub fn wrap_key<C: Crypto>(&self, crypto: &C) -> Zeroizing<[u8; KEY_LEN]> {
        hkdf_sha256(crypto, &[], &self.root[..], b"credential-wrap", &[])
    }

    /// The private key of a seed-recoverable credential with credential seed `cs`:
    /// `HKDF-SHA-256(K_cred, salt = cs, info = "es256" || ctr)` for the first one-byte `ctr` from 0
    /// that gives `0 < d < n`. Rejection keeps the key uniform; reducing modulo `n` would bias it.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] when all 256 counters are rejected, which happens with
    /// probability below 2^-8000.
    pub fn credential_key<C: Crypto>(
        &self,
        crypto: &C,
        cs: &[u8; KEY_LEN],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
        let credential = hkdf_sha256(crypto, &[], &self.root[..], b"credential-key", &[]);
        for counter in 0..=u8::MAX {
            let candidate = hkdf_sha256(crypto, cs, &credential[..], b"es256", &[counter]);
            if is_p256_private_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(CryptoError::InvalidKey)
    }
}

#[cfg(test)]
mod tests;
