//! Host companion tool for the Structured Passkeys device application.

use clap::Parser;

/// Host companion for the Structured Passkeys FIDO2 application on Ledger devices.
#[derive(Parser)]
#[command(version, about)]
struct Cli {}

fn main() {
    Cli::parse();
}
