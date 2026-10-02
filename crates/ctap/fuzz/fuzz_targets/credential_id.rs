//! Fuzz target: opening credential IDs and parsing their authenticated plaintext.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/support/credential_id_harness.rs"]
mod harness;

fuzz_target!(|data: &[u8]| harness::run(data));
