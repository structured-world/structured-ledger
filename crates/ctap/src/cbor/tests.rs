//! CTAP2 canonical CBOR against RFC 8949 Appendix A encodings and the rules of CTAP 2.2 §8.
//! Expected bytes are written out from those documents, never produced by the code under test.

use super::{Decoder, Encoder, Error, Full, Key, MAX_NESTING, validate};

/// Encodes with `write` into a fresh buffer and returns the bytes.
fn encode(write: impl FnOnce(&mut Encoder<'_>) -> Result<(), Full>) -> Vec<u8> {
    let mut buffer = [0u8; 64];
    let mut encoder = Encoder::new(&mut buffer);
    write(&mut encoder).expect("fits");
    encoder.as_bytes().to_vec()
}

/// Integers from RFC 8949 Appendix A decode to their value and encode back to the same bytes,
/// at every width boundary of §8's shortest-form rule.
#[test]
fn integers_follow_the_appendix_a_encodings() {
    let cases: [(i64, &[u8]); 14] = [
        (0, &[0x00]),
        (1, &[0x01]),
        (10, &[0x0A]),
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (100, &[0x18, 0x64]),
        (1000, &[0x19, 0x03, 0xE8]),
        (1_000_000, &[0x1A, 0x00, 0x0F, 0x42, 0x40]),
        (
            1_000_000_000_000,
            &[0x1B, 0x00, 0x00, 0x00, 0xE8, 0xD4, 0xA5, 0x10, 0x00],
        ),
        (-1, &[0x20]),
        (-10, &[0x29]),
        (-100, &[0x38, 0x63]),
        (-1000, &[0x39, 0x03, 0xE7]),
        (
            i64::MIN,
            &[0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        ),
    ];
    for (value, bytes) in cases {
        let mut decoder = Decoder::new(bytes);
        assert_eq!(decoder.int(), Ok(value), "{bytes:02x?}");
        decoder.finish().expect("one item");
        assert_eq!(encode(|e| e.int(value).map(|_| ())), bytes, "{value}");
    }
    let mut largest = Decoder::new(&[0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(largest.unsigned(), Ok(u64::MAX));
}

/// An integer outside `i64` is a type error for `int`, not a crash or a wrap.
#[test]
fn integers_outside_i64_are_unexpected() {
    let too_big = [0x1B, 0x80, 0, 0, 0, 0, 0, 0, 0];
    let too_small = [0x3B, 0x80, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(Decoder::new(&too_big).int(), Err(Error::UnexpectedType));
    assert_eq!(Decoder::new(&too_small).int(), Err(Error::UnexpectedType));
    assert_eq!(validate(&too_small), Ok(()), "well-formed all the same");
}

/// §8: every integer and length uses the shortest form; a longer one is not canonical.
#[test]
fn longer_than_needed_encodings_are_not_canonical() {
    let cases: [&[u8]; 8] = [
        &[0x18, 0x17],
        &[0x19, 0x00, 0xFF],
        &[0x1A, 0x00, 0x00, 0xFF, 0xFF],
        &[0x1B, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
        &[0x38, 0x00],
        &[0x58, 0x01, 0xAA],
        &[0x78, 0x00],
        &[0x98, 0x00],
    ];
    for bytes in cases {
        assert_eq!(validate(bytes), Err(Error::NotCanonical), "{bytes:02x?}");
    }
}

/// Strings borrow from the input; text is checked as UTF-8 (Appendix A vectors).
#[test]
fn strings_follow_the_appendix_a_encodings() {
    let mut decoder = Decoder::new(&[0x44, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!(decoder.bytes(), Ok(&[1, 2, 3, 4][..]));
    assert_eq!(Decoder::new(&[0x40]).bytes(), Ok(&[][..]));
    assert_eq!(
        Decoder::new(&[0x64, 0x49, 0x45, 0x54, 0x46]).text(),
        Ok("IETF")
    );
    assert_eq!(Decoder::new(&[0x62, 0xC3, 0xBC]).text(), Ok("\u{fc}"));
    assert_eq!(
        Decoder::new(&[0x64, 0xF0, 0x90, 0x85, 0x91]).text(),
        Ok("\u{10151}")
    );
    assert_eq!(
        validate(&[0x62, 0xC3, 0x28]),
        Err(Error::Malformed),
        "invalid UTF-8"
    );
    assert_eq!(
        encode(|e| e.text("IETF").map(|_| ())),
        [0x64, 0x49, 0x45, 0x54, 0x46]
    );
    assert_eq!(encode(|e| e.bytes(&[1, 2]).map(|_| ())), [0x42, 0x01, 0x02]);
}

/// A length larger than what is left is malformed before anything is read: no count from the
/// message exceeds the received bytes.
#[test]
fn lengths_beyond_the_input_are_malformed() {
    let cases: [&[u8]; 5] = [
        &[0x45, 0x01],
        &[0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        &[0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        &[0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        &[0xA1, 0x01],
    ];
    for bytes in cases {
        assert_eq!(validate(bytes), Err(Error::Malformed), "{bytes:02x?}");
    }
}

/// Truncated items, reserved additional information, a break outside indefinite items and
/// trailing bytes are not well-formed (RFC 8949 §3).
#[test]
fn malformed_items_are_refused() {
    let cases: [&[u8]; 9] = [
        &[],
        &[0x18],
        &[0x19, 0x03],
        &[0x1C],
        &[0x3E],
        &[0xFF],
        &[0xF8, 0x1F],
        &[0x82, 0x01],
        &[0x01, 0x02],
    ];
    for bytes in cases {
        assert_eq!(validate(bytes), Err(Error::Malformed), "{bytes:02x?}");
    }
}

/// §8: indefinite-length strings, arrays and maps are not canonical, and tags are forbidden.
#[test]
fn indefinite_lengths_and_tags_are_refused() {
    for bytes in [
        &[0x5F, 0xFF][..],
        &[0x7F, 0xFF],
        &[0x9F, 0xFF],
        &[0xBF, 0xFF],
    ] {
        assert_eq!(validate(bytes), Err(Error::NotCanonical), "{bytes:02x?}");
    }
    assert_eq!(validate(&[0xC1, 0x01]), Err(Error::Malformed), "tag 1");
    assert_eq!(
        validate(&[0xD8, 0x20, 0x60]),
        Err(Error::Malformed),
        "tag 32"
    );
}

/// Simple values and floats are well-formed; floats keep their width (§8), so a half-precision
/// value is canonical as it is.
#[test]
fn simple_values_and_floats_are_well_formed() {
    for bytes in [
        &[0xF4][..],
        &[0xF5],
        &[0xF6],
        &[0xF7],
        &[0xF0],
        &[0xF8, 0xFF],
        &[0xF9, 0x3C, 0x00],
        &[0xFA, 0x47, 0xC3, 0x50, 0x00],
        &[0xFB, 0x3F, 0xF1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9A],
    ] {
        assert_eq!(validate(bytes), Ok(()), "{bytes:02x?}");
    }
    assert_eq!(Decoder::new(&[0xF5]).bool(), Ok(true));
    assert_eq!(Decoder::new(&[0xF4]).bool(), Ok(false));
    assert_eq!(Decoder::new(&[0xF6]).bool(), Err(Error::UnexpectedType));
    assert_eq!(
        encode(|e| e.bool(true)?.bool(false)?.null().map(|_| ())),
        [0xF5, 0xF4, 0xF6]
    );
}

/// §8 key order: lower major type first, then the shorter encoding, then bytewise; keys of
/// the same value twice are out of order too.
#[test]
fn map_keys_must_be_in_canonical_order() {
    // {10: 1, 100: 2, -1: 3, "a": 4, "b": 5, "aa": 6}
    let canonical = [
        0xA6, 0x0A, 0x01, 0x18, 0x64, 0x02, 0x20, 0x03, 0x61, b'a', 0x04, 0x61, b'b', 0x05, 0x62,
        b'a', b'a', 0x06,
    ];
    assert_eq!(validate(&canonical), Ok(()));
    let cases: [&[u8]; 5] = [
        // 100 before 10: longer first.
        &[0xA2, 0x18, 0x64, 0x01, 0x0A, 0x02],
        // "b" before "a": bytewise.
        &[0xA2, 0x61, b'b', 0x01, 0x61, b'a', 0x02],
        // "aa" before "b": longer first.
        &[0xA2, 0x62, b'a', b'a', 0x01, 0x61, b'b', 0x02],
        // "a" before 1: higher major type first.
        &[0xA2, 0x61, b'a', 0x01, 0x01, 0x02],
        // 1 twice.
        &[0xA2, 0x01, 0x01, 0x01, 0x02],
    ];
    for bytes in cases {
        assert_eq!(validate(bytes), Err(Error::NotCanonical), "{bytes:02x?}");
    }
}

/// Keys come back typed; values the caller does not read are skipped, and entries after an
/// early stop are still checked.
#[test]
fn map_reading_skips_what_the_caller_leaves() {
    // {1: [1, 2], 2: "x", 3: {4: 5}}
    let message = [
        0xA3, 0x01, 0x82, 0x01, 0x02, 0x02, 0x61, b'x', 0x03, 0xA1, 0x04, 0x05,
    ];
    let mut decoder = Decoder::new(&message);
    let text = decoder.map(|entries| {
        let mut text = None;
        while let Some(key) = entries.next_key()? {
            if key == Key::Int(2) {
                text = Some(entries.value().text()?);
            }
        }
        Ok(text)
    });
    assert_eq!(text, Ok(Some("x")));
    decoder.finish().expect("whole message read");

    // Stopping after the first key still checks the order of the rest.
    let unordered = [0xA3, 0x01, 0x01, 0x03, 0x03, 0x02, 0x02];
    let mut decoder = Decoder::new(&unordered);
    let first = decoder.map(|entries| entries.next_key());
    assert_eq!(first, Err(Error::NotCanonical));
}

/// Text keys and keys of other types read as such.
#[test]
fn keys_are_typed() {
    let message = [0xA3, 0x20, 0x01, 0x41, 0x00, 0x02, 0x62, b'u', b'p', 0x03];
    let mut decoder = Decoder::new(&message);
    let keys = decoder.map(|entries| {
        let mut keys = Vec::new();
        while let Some(key) = entries.next_key()? {
            keys.push(key);
        }
        Ok(keys)
    });
    assert_eq!(keys, Ok(vec![Key::Int(-1), Key::Other, Key::Text("up")]));
}

/// §8: four levels of maps and arrays are supported, a fifth is refused, also inside a value
/// that is only skipped.
#[test]
fn nesting_is_limited_to_four_levels() {
    let four = [0x81, 0x81, 0x81, 0x81, 0x01];
    let five = [0x81, 0x81, 0x81, 0x81, 0x81, 0x01];
    assert_eq!(MAX_NESTING, 4);
    assert_eq!(validate(&four), Ok(()));
    assert_eq!(validate(&five), Err(Error::TooDeep));
    // {1: [[[[1]]]]}: the map is the first level.
    let skipped = [0xA1, 0x01, 0x81, 0x81, 0x81, 0x81, 0x01];
    let mut decoder = Decoder::new(&skipped);
    assert_eq!(
        decoder.map(|entries| entries.next_key().map(|_| ())),
        Err(Error::TooDeep)
    );
}

/// Array elements the caller does not read are skipped and checked.
#[test]
fn array_reading_skips_the_rest() {
    let message = [0x83, 0x01, 0x61, b'a', 0x18, 0x17];
    let mut decoder = Decoder::new(&message);
    let first = decoder.array(|elements| {
        assert_eq!(elements.remaining(), 3);
        elements.next_element().expect("one element").unsigned()
    });
    assert_eq!(
        first,
        Err(Error::NotCanonical),
        "the skipped 0x18 0x17 is checked"
    );
}

/// The encoder writes the shortest forms and a nested structure that the decoder accepts.
#[test]
fn encoded_maps_and_arrays_are_canonical() {
    // {1: ["a", -7], 2: h'00ff'}
    let bytes = encode(|e| {
        e.map(2)?
            .unsigned(1)?
            .array(2)?
            .text("a")?
            .int(-7)?
            .unsigned(2)?;
        e.bytes(&[0x00, 0xFF]).map(|_| ())
    });
    assert_eq!(
        bytes,
        [0xA2, 0x01, 0x82, 0x61, b'a', 0x26, 0x02, 0x42, 0x00, 0xFF]
    );
    assert_eq!(validate(&bytes), Ok(()));
}

/// Writing past the buffer reports `Full` and keeps what was written.
#[test]
fn a_full_encoder_reports_it() {
    let mut buffer = [0u8; 3];
    let mut encoder = Encoder::new(&mut buffer);
    assert!(encoder.unsigned(1000).is_ok());
    assert_eq!(encoder.unsigned(1).map(|_| ()), Err(Full));
    assert_eq!(encoder.as_bytes(), [0x19, 0x03, 0xE8]);
    assert_eq!(encoder.len(), 3);
}
