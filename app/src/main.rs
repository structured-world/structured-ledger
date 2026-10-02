//! Device application: shows the home screen, runs the FIDO HID interface and answers the Ledger
//! APDU channel.

#![no_std]
#![no_main]

mod hid;

use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::{self, CommError, CommandOrEvent, DecodedEventType, StatusWords};
use ledger_device_sdk::nbgl::{NbglGlyph, NbglHomeAndSettings};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM);

/// Name on the home screen; the same as `package.metadata.ledger.name`.
const APP_NAME: &str = "Structured Passkeys";

/// Class byte of the Ledger management channel; the SDK rejects other classes.
const CLA: u8 = 0xE0;

#[cfg(target_os = "apex_p")]
const HOME_GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/key_48x48.png", NBGL));
#[cfg(any(target_os = "stax", target_os = "flex"))]
const HOME_GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/key_64x64.png", NBGL));
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const HOME_GLYPH: NbglGlyph =
    NbglGlyph::from_include(include_gif!("glyphs/key_nano_14x14.png", NBGL));

#[unsafe(no_mangle)]
extern "C" fn sample_main(_arg0: u32) {
    hid::start();
    let comm = io::init_comm(&COMM);
    comm.set_expected_cla(CLA);

    // The home screen carries the version page and the quit action.
    let mut home = NbglHomeAndSettings::new().glyph(&HOME_GLYPH).infos(
        APP_NAME,
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_AUTHORS"),
    );
    home.show_and_return();

    // FIDO HID reports reach the transport through the USB class callbacks during each event;
    // the loop only gives the transport its clock and answers the management channel.
    loop {
        match comm.next_command_or_event() {
            CommandOrEvent::Command(command) => {
                // No management command is implemented: ISO/IEC 7816-4 5.6, SW 6D00
                // "instruction code not supported or invalid". The SDK names 0x6D00 `Unknown`;
                // its `BadIns` is 0x6E01.
                match command.reply(&[], StatusWords::Unknown) {
                    // An empty reply cannot overflow, and a reply that failed to leave the
                    // device has no one to report to: the host times out and the loop takes
                    // its next command.
                    Ok(()) | Err(CommError::Overflow | CommError::IoError) => {}
                }
            }
            CommandOrEvent::Event(DecodedEventType::Ticker) => hid::tick(),
            CommandOrEvent::Event(_) => {}
        }
    }
}
