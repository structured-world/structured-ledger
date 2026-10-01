//! Command-line surface of the `structured-ledger` binary.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_structured-ledger"))
        .args(args)
        .output()
        .expect("the binary cargo built for this test starts")
}

/// `--version` prints the binary name and the manifest version and exits successfully; a missing
/// or reformatted version line would break scripts that check the installed tool.
#[test]
fn version_prints_name_and_manifest_version() {
    let output = run(&["--version"]);
    assert_eq!(output.status.code(), Some(0));
    // The expected version is the manifest's, not the binary's own output.
    let expected = format!("structured-ledger {}\n", env!("CARGO_PKG_VERSION"));
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
    assert!(output.stderr.is_empty());
}

/// An unknown option is a usage error: exit status 2 and a message on stderr, nothing on stdout,
/// so a typo is never mistaken for a successful run.
#[test]
fn unknown_option_is_a_usage_error() {
    let output = run(&["--no-such-option"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("unexpected argument '--no-such-option'"),
        "{stderr}"
    );
}
