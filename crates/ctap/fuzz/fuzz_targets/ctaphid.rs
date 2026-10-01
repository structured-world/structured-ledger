//! Fuzz target: CTAPHID reassembly and framing from arbitrary report sequences.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/support/ctaphid_harness.rs"]
mod harness;

fuzz_target!(|data: &[u8]| harness::run(data));
