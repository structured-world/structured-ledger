//! CTAP2 canonical CBOR decoding driven by arbitrary bytes, shared by the fuzz target and the
//! regression test of its corpus. Every accepted input is checked against properties the
//! encoding guarantees, so a decoder that accepts too much fails here.

use structured_passkeys_ctap::cbor::{Decoder, Error, MAX_NESTING, validate};

/// Runs one input; panics on any broken property.
pub fn run(data: &[u8]) {
    let verdict = validate(data);
    // Reading the input as a CTAP request map gives the same verdict whenever it is one.
    if data.first().is_some_and(|byte| byte >> 5 == 5) {
        let mut decoder = Decoder::new(data);
        let read = decoder
            .map(|entries| {
                while entries.next_key()?.is_some() {}
                Ok(())
            })
            .and_then(|()| decoder.finish());
        assert_eq!(read, verdict, "map reading and validation disagree");
    }
    if verdict.is_err() {
        return;
    }
    // One definite-length item ends exactly where its encoding ends: a byte more is trailing
    // data, a byte less is truncated.
    let mut longer = data.to_vec();
    longer.push(0x00);
    assert_eq!(
        validate(&longer),
        Err(Error::Malformed),
        "trailing byte accepted"
    );
    for end in 0..data.len() {
        assert!(
            validate(&data[..end]).is_err(),
            "prefix of {end} bytes accepted"
        );
    }
    // Every accepted input fits the nesting limit: wrapping it in more arrays than the limit
    // allows is refused.
    let mut wrapped = vec![0x81; usize::from(MAX_NESTING)];
    wrapped.extend_from_slice(data);
    let nested = data.first().is_some_and(|byte| matches!(byte >> 5, 4 | 5));
    if nested {
        assert_eq!(
            validate(&wrapped),
            Err(Error::TooDeep),
            "nesting limit not enforced"
        );
    }
}
