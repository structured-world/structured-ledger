//! COSE keys and packed self attestation: encodings written out by hand from RFC 9052/9053 and
//! WebAuthn L3 §8.2, signatures checked with the independent `p256` verifier.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{DerSignature, VerifyingKey};

use super::{ES256, encode_cose_key, encode_packed_statement, sign_self_attestation};
use crate::cbor::{Encoder, validate};
use crate::crypto::{Crypto, KEY_LEN, PUBLIC_KEY_LEN};
use crate::soft::SoftCrypto;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// The credential key of the derivation vectors (tests/vectors/derive.py).
fn private_key() -> [u8; KEY_LEN] {
    hex("1c25ee63dee5fe30ce9c52ab615f52ac394a85337799970d800c083971cfb721")
        .try_into()
        .expect("32 bytes")
}

fn public_key() -> [u8; PUBLIC_KEY_LEN] {
    hex("045d31fcf65ebd9f1f252c1d9fd97dd225f3bf7dde1c4967b09457ca4156889a0407903bd11c6253ad24a56919c313027951af0759d9ce749aa8bbcf62290f718b")
        .try_into()
        .expect("65 bytes")
}

/// The COSE_Key is `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` in canonical key order (unsigned keys
/// before negative ones): A5 01 02 03 26 20 01 21 58 20 x 22 58 20 y.
#[test]
fn the_cose_key_is_ec2_es256_p256() {
    let public_key = public_key();
    let mut buffer = [0u8; 128];
    let mut encoder = Encoder::new(&mut buffer);
    encode_cose_key(&mut encoder, &public_key).expect("fits");
    let expected = [
        &[0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20][..],
        &public_key[1..33],
        &[0x22, 0x58, 0x20],
        &public_key[33..],
    ]
    .concat();
    assert_eq!(encoder.as_bytes(), &expected[..]);
    assert_eq!(validate(encoder.as_bytes()), Ok(()));
}

/// The self-attestation signature verifies under the credential public key over SHA-256 of
/// authenticatorData || clientDataHash; over anything else it does not.
#[test]
fn self_attestation_signs_auth_data_and_client_data_hash() {
    let mut crypto = SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]);
    let auth_data = [0xAD; 37];
    let client_data_hash = [0xCD; KEY_LEN];
    let signature =
        sign_self_attestation(&mut crypto, &private_key(), &auth_data, &client_data_hash)
            .expect("valid key");
    let verifier = VerifyingKey::from_sec1_bytes(&public_key()).expect("valid point");
    let der = DerSignature::from_bytes(signature.as_der()).expect("DER signature");
    let digest = crypto.sha256(&[&auth_data, &client_data_hash]);
    assert!(verifier.verify_prehash(&digest, &der).is_ok());
    let other = crypto.sha256(&[&auth_data, &[0xCE; KEY_LEN]]);
    assert!(verifier.verify_prehash(&other, &der).is_err());
}

/// attStmt is `{"alg": -7, "sig": signature}` with "alg" first (equal lengths, bytewise order)
/// and no x5c: A2 63 'alg' 26 63 'sig' 58 len signature.
#[test]
fn the_packed_statement_is_alg_and_sig() {
    let mut crypto = SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN]);
    let signature = crypto
        .p256_sign(&private_key(), &[0x5A; KEY_LEN])
        .expect("valid key");
    let mut buffer = [0u8; 128];
    let mut encoder = Encoder::new(&mut buffer);
    encode_packed_statement(&mut encoder, &signature).expect("fits");
    let der = signature.as_der();
    let expected = [
        &[
            0xA2, 0x63, b'a', b'l', b'g', 0x26, 0x63, b's', b'i', b'g', 0x58,
        ][..],
        &[u8::try_from(der.len()).expect("short")],
        der,
    ]
    .concat();
    assert_eq!(encoder.as_bytes(), &expected[..]);
    assert_eq!(validate(encoder.as_bytes()), Ok(()));
    assert_eq!(ES256, -7);
}
