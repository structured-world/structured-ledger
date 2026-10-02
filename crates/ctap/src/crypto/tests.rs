//! HKDF against the RFC 5869 Appendix A vectors and the P-256 private-key range check at its
//! boundaries. Expected bytes are copied from the specifications. Also the software platform's
//! redacted Debug output.

use super::{KEY_LEN, hkdf_sha256, is_p256_private_key};
use crate::soft::SoftCrypto;

fn crypto() -> SoftCrypto {
    SoftCrypto::new([0x11; KEY_LEN], [0x22; KEY_LEN])
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// RFC 5869 A.1: the first 32 bytes of OKM are T(1), the block this HKDF returns. A wrong salt,
/// IKM or info order gives a different block.
#[test]
fn hkdf_matches_rfc5869_test_case_1() {
    let ikm = [0x0B; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");
    let okm = hkdf_sha256(&crypto(), &salt, &ikm, &info, &[]);
    assert_eq!(
        okm[..],
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")[..]
    );
    // The info split between label and suffix is the same info.
    let split = hkdf_sha256(&crypto(), &salt, &ikm, &info[..5], &info[5..]);
    assert_eq!(split[..], okm[..]);
}

/// RFC 5869 A.3: an empty salt is HashLen zeros and an empty info is allowed.
#[test]
fn hkdf_matches_rfc5869_test_case_3() {
    let okm = hkdf_sha256(&crypto(), &[], &[0x0B; 22], &[], &[]);
    assert_eq!(
        okm[..],
        hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d")[..]
    );
}

/// A P-256 private key is 0 < d < n (SEC 1 §3.2.1): zero, n and above are refused, 1 and n - 1
/// accepted. A check that compared the wrong way round or forgot zero would pass a bad key.
#[test]
fn p256_private_keys_are_between_zero_and_the_order() {
    let order = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let key = |bytes: &[u8]| -> [u8; KEY_LEN] { bytes.try_into().expect("32 bytes") };
    let mut below = key(&order);
    below[KEY_LEN - 1] = 0x50;
    let mut above = key(&order);
    above[KEY_LEN - 1] = 0x52;
    let mut one = [0u8; KEY_LEN];
    one[KEY_LEN - 1] = 1;

    assert!(!is_p256_private_key(&[0u8; KEY_LEN]), "zero");
    assert!(is_p256_private_key(&one), "one");
    assert!(is_p256_private_key(&below), "n - 1");
    assert!(!is_p256_private_key(&key(&order)), "n");
    assert!(!is_p256_private_key(&above), "n + 1");
    assert!(!is_p256_private_key(&[0xFF; KEY_LEN]), "2^256 - 1");
    // A difference only in the top byte: 0x7F... is far below n.
    let mut high = [0u8; KEY_LEN];
    high[0] = 0x7F;
    assert!(is_p256_private_key(&high), "0x7f00..00");
}

/// The software platform's node derives every key and its seed predicts every nonce: Debug
/// output prints neither.
#[test]
fn soft_crypto_debug_output_hides_the_node_and_the_seed() {
    let debug = format!("{:?}", crypto());
    assert_eq!(debug, "SoftCrypto { counter: 0, .. }");
}
