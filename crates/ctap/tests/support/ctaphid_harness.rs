//! CTAPHID reassembly driven by arbitrary bytes, shared by the fuzz target and the regression
//! test of its corpus.
//!
//! The input is a sequence of 66-byte steps: a time step in milliseconds, a flag byte, then one
//! 64-byte report. Every event is checked against the invariants the device relies on.

use structured_passkeys_ctap::ctaphid::{Command, Event, Frames, REPORT_SIZE, Report, Transport};

/// Buffer size of the harness: small enough that BCNT above it is common.
const BUFFER: usize = 1024;

/// Bytes of one step: time step, flag, report.
const STEP: usize = 2 + REPORT_SIZE;

/// Runs one input; panics on any broken invariant.
pub fn run(data: &[u8]) {
    let mut transport = Transport::<BUFFER>::new(structured_passkeys_ctap::ctaphid::DeviceInfo {
        version: [0, 1, 0],
        capabilities: 0x04,
    });
    let mut now: u64 = 0;
    let (steps, _) = data.as_chunks::<STEP>();
    for step in steps {
        now += u64::from(step[0]);
        let finish_after = step[1] & 1 == 1;
        let mut report: Report = [0; REPORT_SIZE];
        report.copy_from_slice(&step[2..]);
        let active_before = transport.active();
        // CTAPHID_CANCEL with the initialization bit.
        let is_cancel = report[4] == 0x91;
        match transport.receive(&report, now) {
            Event::None => {}
            Event::Reply {
                cid,
                command,
                payload,
            } => {
                // §11.2.9.1.5: CANCEL is never answered, whatever the state.
                assert!(!is_cancel, "CANCEL answered with {command:?}");
                assert!(payload.len() <= BUFFER.max(17));
                assert!(matches!(
                    command,
                    Command::Init | Command::Ping | Command::Error
                ));
                if command == Command::Error {
                    assert_eq!(payload.len(), 1);
                }
                let frames: Vec<Report> = Frames::new(cid, command, payload)
                    .expect("replies fit the framing")
                    .collect();
                let expected = if payload.len() <= 57 {
                    1
                } else {
                    1 + (payload.len() - 57).div_ceil(59)
                };
                assert_eq!(frames.len(), expected);
                for frame in &frames {
                    assert_eq!(frame[..4], cid.to_be_bytes());
                }
            }
            Event::Request {
                cid,
                command,
                payload,
            } => {
                assert!(matches!(command, Command::Msg | Command::Cbor));
                assert!(payload.len() <= BUFFER);
                assert_eq!(transport.active(), Some(cid));
                if finish_after {
                    transport.finish();
                }
            }
            Event::Cancel { cid } => {
                assert_eq!(active_before, Some(cid));
                assert_eq!(transport.active(), Some(cid));
            }
        }
    }
}
