//! Regression corpus of the credential ID fuzz target, replayed on the stable toolchain so every
//! input that once mattered (seeds and past findings) keeps passing the harness properties.

#[path = "support/credential_id_harness.rs"]
mod harness;

use std::fs;
use std::path::Path;

/// Every file of `fuzz/corpus/credential-id` passes the harness; an empty corpus is a mistake,
/// not a pass.
#[test]
fn credential_id_corpus_passes_the_harness() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/credential-id");
    let mut count = 0usize;
    for entry in fs::read_dir(&dir).expect("corpus directory exists") {
        let path = entry.expect("readable corpus entry").path();
        let data = fs::read(&path).expect("readable corpus file");
        harness::run(&data);
        count = count.checked_add(1).expect("a corpus fits usize");
    }
    assert!(count > 0, "no corpus in {}", dir.display());
}
