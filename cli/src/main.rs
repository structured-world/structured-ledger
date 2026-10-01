//! Host companion tool for the structured-ledger device application.

use clap::Parser;

/// Host companion for the structured-ledger FIDO2 application on Ledger devices.
#[derive(Parser)]
#[command(version, about)]
struct Cli {}

fn main() {
    Cli::parse();
}
