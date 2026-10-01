//! CTAPHID reassembly driven by arbitrary bytes, shared by the fuzz target and the regression
//! test of its corpus.
//!
//! The input is a sequence of 66-byte steps: a time step in milliseconds, a flag byte, then one
//! 64-byte report. Flag bit 0 finishes a request handed out by the step, bit 1 turns the step
//! into a timer poll without a report. Every event is checked against the invariants the device
//! relies on.

use structured_passkeys_ctap::ctaphid::{
    BROADCAST_CID, Command, Event, Frames, REPORT_SIZE, Report, Transport,
};

/// Buffer size of the harness: small enough that BCNT above it is common.
const BUFFER: usize = 1024;

/// Bytes of one step: time step, flag, report.
const STEP: usize = 2 + REPORT_SIZE;

/// Runs one input; panics on any broken invariant.
pub fn run(data: &[u8]) {
    let mut transport = Transport::<BUFFER>::new(structured_passkeys_ctap::ctaphid::DeviceInfo {
        version: [0, 1, 0],
        cbor: true,
        msg: true,
    });
    // Channels handed out by INIT replies on the broadcast channel (§11.2.3).
    let mut allocated: Vec<u32> = Vec::new();
    let mut now: u64 = 0;
    let (steps, _) = data.as_chunks::<STEP>();
    for step in steps {
        now += u64::from(step[0]);
        let finish_after = step[1] & 1 == 1;
        if step[1] & 2 == 2 {
            // A poll only ever reports a timeout, and only to the channel whose message stalled.
            match transport.poll(now) {
                Event::None => {}
                Event::Reply {
                    command: Command::Error,
                    payload: [0x05],
                    ..
                } => {}
                other => panic!("poll returned {other:?}"),
            }
            continue;
        }
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
                if command == Command::Init {
                    assert_eq!(payload.len(), 17);
                    let channel =
                        u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
                    if cid == BROADCAST_CID {
                        // A fresh channel each time, never a reserved one.
                        assert!(channel != 0 && channel != BROADCAST_CID);
                        assert!(!allocated.contains(&channel), "channel {channel} reused");
                        allocated.push(channel);
                    } else {
                        // INIT on a channel confirms that channel, which must be allocated.
                        assert_eq!(channel, cid);
                        assert!(allocated.contains(&cid), "INIT on unallocated {cid}");
                    }
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
                // §11.2.3: requests only on allocated channels, never 0 or the broadcast one.
                assert!(allocated.contains(&cid), "request on unallocated {cid}");
                assert!(payload.len() <= BUFFER);
                assert_eq!(transport.active(), Some(cid));
                if finish_after {
                    transport.finish();
                }
            }
            Event::Cancel { cid } => {
                assert!(allocated.contains(&cid), "cancel on unallocated {cid}");
                assert_eq!(active_before, Some(cid));
                assert_eq!(transport.active(), Some(cid));
            }
        }
    }
}
