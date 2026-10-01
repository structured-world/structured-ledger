//! Regression corpus of the CTAPHID fuzz target, replayed on the stable toolchain so every
//! input that once mattered (seeds and past findings) keeps passing the harness invariants.

#[path = "support/ctaphid_harness.rs"]
mod harness;

use std::fs;
use std::path::Path;

/// Every file of `fuzz/corpus/ctaphid` passes the harness; an empty corpus is a mistake, not
/// a pass.
#[test]
fn ctaphid_corpus_passes_the_harness() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/ctaphid");
    let mut count = 0;
    for entry in fs::read_dir(&dir).expect("corpus directory exists") {
        let path = entry.expect("readable corpus entry").path();
        let data = fs::read(&path).expect("readable corpus file");
        harness::run(&data);
        count += 1;
    }
    assert!(count > 0, "no corpus in {}", dir.display());
}
