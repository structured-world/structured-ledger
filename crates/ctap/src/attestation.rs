//! Credential public keys in COSE form and packed self attestation.
//!
//! Self attestation (WebAuthn L3 §8.2, packed format without `x5c`): the statement is signed by
//! the credential's own private key, so nothing secret is compiled into the application.

use crate::cbor::{Encoder, Full};
use crate::crypto::{Crypto, CryptoError, KEY_LEN, PUBLIC_KEY_LEN, Signature};

/// COSE algorithm ES256: ECDSA with SHA-256 on P-256 (RFC 9053 §2.1).
pub const ES256: i64 = -7;

/// COSE key type EC2 (RFC 9053 §7.1).
const KTY_EC2: u64 = 2;
/// COSE curve P-256 (RFC 9053 §7.1).
const CRV_P256: u64 = 1;

/// Writes an uncompressed P-256 public key as a COSE_Key map `{1: 2, 3: -7, -1: 1, -2: x, -3:
/// y}` (RFC 9052 §7, RFC 9053 §7.1.1), keys in CTAP2 canonical order.
///
/// # Errors
///
/// [`Full`] when the buffer has no room.
pub fn encode_cose_key(
    encoder: &mut Encoder<'_>,
    public_key: &[u8; PUBLIC_KEY_LEN],
) -> Result<(), Full> {
    let (x, y) = public_key[1..].split_at(KEY_LEN);
    encoder
        .map(5)?
        .unsigned(1)?
        .unsigned(KTY_EC2)?
        .unsigned(3)?
        .int(ES256)?
        .int(-1)?
        .unsigned(CRV_P256)?
        .int(-2)?
        .bytes(x)?
        .int(-3)?
        .bytes(y)?;
    Ok(())
}

/// The packed self-attestation signature: ECDSA under the credential's private key over
/// `authenticatorData || clientDataHash` (WebAuthn L3 §8.2).
///
/// # Errors
///
/// [`CryptoError::InvalidKey`] for a private key outside P-256's range.
pub fn sign_self_attestation<C: Crypto>(
    crypto: &mut C,
    private_key: &[u8; KEY_LEN],
    authenticator_data: &[u8],
    client_data_hash: &[u8; KEY_LEN],
) -> Result<Signature, CryptoError> {
    let digest = crypto.sha256(&[authenticator_data, client_data_hash]);
    crypto.p256_sign(private_key, &digest)
}

/// Writes the packed attestation statement `{"alg": -7, "sig": signature}` (WebAuthn L3 §8.2,
/// self attestation: no `x5c`).
///
/// # Errors
///
/// [`Full`] when the buffer has no room.
pub fn encode_packed_statement(
    encoder: &mut Encoder<'_>,
    signature: &Signature,
) -> Result<(), Full> {
    encoder
        .map(2)?
        .text("alg")?
        .int(ES256)?
        .text("sig")?
        .bytes(signature.as_der())?;
    Ok(())
}

#[cfg(test)]
mod tests;
