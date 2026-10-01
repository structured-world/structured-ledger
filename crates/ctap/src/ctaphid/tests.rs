//! CTAPHID framing against the packet layouts and rules of CTAP 2.2 §11.2. Every expected report
//! is written out byte by byte from the specification tables, never produced by the code under
//! test.

use super::{
    BROADCAST_CID, Command, DeviceInfo, ErrorCode, Event, Frames, KeepaliveStatus,
    MAX_MESSAGE_SIZE, PACKET_TIMEOUT_MS, Report, TooLong, Transport, UnknownCommand, keepalive,
};

const INFO: DeviceInfo = DeviceInfo {
    version: [1, 2, 3],
    capabilities: 0x04,
};
const NONCE: [u8; 8] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];

/// Initialization packet: CID (big endian), CMD | 0x80, BCNT, then up to 57 data bytes.
fn init_packet(cid: u32, cmd: u8, bcnt: u16, data: &[u8]) -> Report {
    let mut report = [0u8; 64];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = cmd | 0x80;
    report[5..7].copy_from_slice(&bcnt.to_be_bytes());
    report[7..7 + data.len()].copy_from_slice(data);
    report
}

/// Continuation packet: CID, SEQ (bit 7 clear), then up to 59 data bytes.
fn cont_packet(cid: u32, seq: u8, data: &[u8]) -> Report {
    let mut report = [0u8; 64];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = seq;
    report[5..5 + data.len()].copy_from_slice(data);
    report
}

fn error(cid: u32, code: u8) -> (u32, Command, Vec<u8>) {
    (cid, Command::Error, vec![code])
}

/// Copies a reply out so the transport can be used again.
fn reply(event: Event<'_>) -> (u32, Command, Vec<u8>) {
    match event {
        Event::Reply {
            cid,
            command,
            payload,
        } => (cid, command, payload.to_vec()),
        other => panic!("expected a reply, got {other:?}"),
    }
}

/// Allocates channels 1..=count on a fresh transport.
fn with_channels<const N: usize>(count: u32) -> Transport<N> {
    let mut transport = Transport::<N>::new(INFO);
    for _ in 0..count {
        reply(transport.receive(&init_packet(BROADCAST_CID, 0x06, 8, &NONCE), 0));
    }
    transport
}

/// Sends a one-byte CBOR request on `cid` and checks it is handed out.
fn cbor_request<const N: usize>(transport: &mut Transport<N>, cid: u32) {
    match transport.receive(&init_packet(cid, 0x10, 1, &[0x04]), 0) {
        Event::Request {
            cid: got,
            command: Command::Cbor,
            payload,
        } => {
            assert_eq!((got, payload), (cid, &[0x04][..]));
        }
        other => panic!("expected a CBOR request, got {other:?}"),
    }
}

/// INIT on the broadcast channel allocates ascending channels and answers on the broadcast
/// channel with nonce, channel, protocol version 2, device version and capabilities
/// (§11.2.9.1.3); a wrong response layout breaks every host's channel setup.
#[test]
fn init_on_broadcast_allocates_ascending_channels() {
    let mut transport = Transport::<1024>::new(INFO);
    let first = reply(transport.receive(&init_packet(BROADCAST_CID, 0x06, 8, &NONCE), 0));
    let expected: Vec<u8> = [
        &NONCE[..],
        &[0x00, 0x00, 0x00, 0x01],
        &[0x02],
        &[1, 2, 3],
        &[0x04],
    ]
    .concat();
    assert_eq!(first, (BROADCAST_CID, Command::Init, expected));
    let second = reply(transport.receive(&init_packet(BROADCAST_CID, 0x06, 8, &NONCE), 0));
    assert_eq!(second.2[8..12], [0x00, 0x00, 0x00, 0x02]);
}

/// INIT on an allocated channel resynchronizes it and answers with that same channel, on that
/// channel (§11.2.9.1.3).
#[test]
fn init_on_an_allocated_channel_confirms_it() {
    let mut transport = with_channels::<1024>(3);
    let (cid, command, payload) = reply(transport.receive(&init_packet(2, 0x06, 8, &NONCE), 0));
    assert_eq!((cid, command), (2, Command::Init));
    assert_eq!(payload[8..12], [0, 0, 0, 2]);
}

/// INIT carries exactly an 8-byte nonce; any other BCNT is ERR_INVALID_LEN (§11.2.9.1.3).
#[test]
fn init_with_a_wrong_length_is_invalid_len() {
    let mut transport = Transport::<1024>::new(INFO);
    for bcnt in [0, 7, 9, 57] {
        let event = transport.receive(&init_packet(BROADCAST_CID, 0x06, bcnt, &[0; 9]), 0);
        assert_eq!(reply(event), error(BROADCAST_CID, 0x03), "BCNT {bcnt}");
    }
}

/// Channel 0, unallocated channels, and the broadcast channel with anything but INIT are
/// ERR_INVALID_CHANNEL (§11.2.3), so a host cannot skip channel allocation.
#[test]
fn reserved_unallocated_and_broadcast_channels_are_invalid() {
    let mut transport = with_channels::<1024>(2);
    let cases = [
        init_packet(0, 0x06, 8, &NONCE),
        init_packet(0, 0x01, 0, &[]),
        init_packet(3, 0x06, 8, &NONCE),
        init_packet(3, 0x10, 1, &[0x04]),
        init_packet(BROADCAST_CID, 0x01, 0, &[]),
        init_packet(BROADCAST_CID, 0x10, 1, &[0x04]),
    ];
    for packet in cases {
        let cid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_eq!(
            reply(transport.receive(&packet, 0)),
            error(cid, 0x0B),
            "{packet:02x?}"
        );
    }
}

/// The last channel identifier is never handed out twice and never becomes the broadcast
/// channel: allocation stops with ERR_OTHER.
#[test]
fn channel_allocation_stops_before_the_broadcast_channel() {
    let mut transport = Transport::<1024>::new(INFO);
    transport.last_cid = BROADCAST_CID - 1;
    let event = transport.receive(&init_packet(BROADCAST_CID, 0x06, 8, &NONCE), 0);
    assert_eq!(reply(event), error(BROADCAST_CID, 0x7F));
}

/// PING echoes its payload, in one packet or reassembled from continuation packets
/// (§11.2.9.1.4, §11.2.4).
#[test]
fn ping_echoes_single_and_multi_packet_payloads() {
    let mut transport = with_channels::<1024>(1);
    assert_eq!(
        reply(transport.receive(&init_packet(1, 0x01, 0, &[]), 0)),
        (1, Command::Ping, Vec::new())
    );
    let data: Vec<u8> = (0..200u8).collect();
    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 200, &data[..57]), 0),
        Event::None
    );
    assert_eq!(
        transport.receive(&cont_packet(1, 0, &data[57..116]), 1),
        Event::None
    );
    assert_eq!(
        transport.receive(&cont_packet(1, 1, &data[116..175]), 2),
        Event::None
    );
    assert_eq!(
        reply(transport.receive(&cont_packet(1, 2, &data[175..]), 3)),
        (1, Command::Ping, data)
    );
}

/// The largest message the framing allows, 7609 bytes in 129 packets with sequence numbers
/// 0..=127, is reassembled when the buffer is that large (§11.2.4).
#[test]
fn the_largest_message_is_reassembled() {
    let mut transport = with_channels::<MAX_MESSAGE_SIZE>(1);
    assert_eq!(MAX_MESSAGE_SIZE, 7609);
    let data: Vec<u8> = (0..7609u32).map(|byte| byte as u8).collect();
    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 7609, &data[..57]), 0),
        Event::None
    );
    for seq in 0..127u8 {
        let start = 57 + usize::from(seq) * 59;
        let event = transport.receive(&cont_packet(1, seq, &data[start..start + 59]), 0);
        assert_eq!(event, Event::None, "seq {seq}");
    }
    let last = transport.receive(&cont_packet(1, 127, &data[57 + 127 * 59..]), 0);
    assert_eq!(reply(last), (1, Command::Ping, data));
}

/// BCNT above the device buffer is ERR_INVALID_LEN at the initialization packet, so nothing is
/// buffered for it; BCNT equal to the buffer is accepted.
#[test]
fn length_above_the_buffer_is_invalid_len() {
    let mut transport = with_channels::<100>(1);
    assert_eq!(
        reply(transport.receive(&init_packet(1, 0x10, 101, &[0; 57]), 0)),
        error(1, 0x03)
    );
    assert_eq!(
        reply(transport.receive(&init_packet(1, 0x10, 0xFFFF, &[0; 57]), 0)),
        error(1, 0x03)
    );
    assert_eq!(
        transport.receive(&init_packet(1, 0x10, 100, &[0; 57]), 0),
        Event::None
    );
}

/// MSG and CBOR requests go to the CTAP layer; until they are finished the device answers
/// ERR_CHANNEL_BUSY to other channels and to new requests on the same channel (§11.2.5.1).
#[test]
fn a_request_keeps_the_device_busy_until_finished() {
    let mut transport = with_channels::<1024>(2);
    match transport.receive(&init_packet(1, 0x03, 3, &[0x00, 0x03, 0x00]), 0) {
        Event::Request {
            cid: 1,
            command: Command::Msg,
            payload,
        } => assert_eq!(payload, [0x00, 0x03, 0x00]),
        other => panic!("{other:?}"),
    }
    assert_eq!(transport.active(), Some(1));
    assert_eq!(
        reply(transport.receive(&init_packet(2, 0x01, 0, &[]), 0)),
        error(2, 0x06)
    );
    assert_eq!(
        reply(transport.receive(&init_packet(BROADCAST_CID, 0x06, 8, &NONCE), 0)),
        error(BROADCAST_CID, 0x06)
    );
    assert_eq!(
        reply(transport.receive(&init_packet(1, 0x01, 0, &[]), 0)),
        error(1, 0x06)
    );
    assert_eq!(transport.receive(&cont_packet(2, 0, &[]), 0), Event::None);
    transport.finish();
    assert_eq!(transport.active(), None);
    assert_eq!(
        reply(transport.receive(&init_packet(2, 0x01, 0, &[]), 0)),
        (2, Command::Ping, Vec::new())
    );
}

/// CANCEL on the active channel reaches the CTAP layer and is never answered; CANCEL anywhere
/// else, including an invalid channel, is ignored (§11.2.9.1.5).
#[test]
fn cancel_reaches_only_the_active_request() {
    let mut transport = with_channels::<1024>(2);
    assert_eq!(
        transport.receive(&init_packet(1, 0x11, 0, &[]), 0),
        Event::None
    );
    assert_eq!(
        transport.receive(&init_packet(0, 0x11, 0, &[]), 0),
        Event::None
    );
    cbor_request(&mut transport, 1);
    assert_eq!(
        transport.receive(&init_packet(2, 0x11, 0, &[]), 0),
        Event::None
    );
    assert_eq!(
        transport.receive(&init_packet(1, 0x11, 0, &[]), 0),
        Event::Cancel { cid: 1 }
    );
    assert_eq!(transport.active(), Some(1), "the CTAP layer still answers");
}

/// CANCEL in the middle of a message on the same channel is never answered (§11.2.9.1.5); the
/// client gave the message up, so it is dropped and its continuation becomes spurious.
#[test]
fn cancel_during_assembly_is_silent_and_drops_the_message() {
    let mut transport = with_channels::<1024>(1);
    assert_eq!(
        transport.receive(&init_packet(1, 0x10, 100, &[0; 57]), 0),
        Event::None
    );
    assert_eq!(
        transport.receive(&init_packet(1, 0x11, 0, &[]), 0),
        Event::None
    );
    assert_eq!(
        transport.receive(&cont_packet(1, 0, &[0; 43]), 0),
        Event::None
    );
    assert_eq!(transport.active(), None);
}

/// INIT on the channel whose request is being processed aborts that transaction: the request is
/// no longer active and the channel is confirmed (§11.2.5.3).
#[test]
fn init_on_the_processing_channel_aborts_its_request() {
    let mut transport = with_channels::<1024>(1);
    cbor_request(&mut transport, 1);
    let (cid, command, payload) = reply(transport.receive(&init_packet(1, 0x06, 8, &NONCE), 0));
    assert_eq!(
        (cid, command, &payload[8..12]),
        (1, Command::Init, &[0, 0, 0, 1][..])
    );
    assert_eq!(transport.active(), None);
}

/// A continuation packet with the wrong sequence number, or an initialization packet other
/// than INIT in the middle of a message, is ERR_INVALID_SEQ and drops the message (§11.2.5.4).
#[test]
fn sequence_errors_drop_the_message() {
    let mut transport = with_channels::<1024>(1);
    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 100, &[0; 57]), 0),
        Event::None
    );
    assert_eq!(
        reply(transport.receive(&cont_packet(1, 1, &[0; 43]), 0)),
        error(1, 0x04)
    );
    assert_eq!(
        transport.receive(&cont_packet(1, 0, &[0; 43]), 0),
        Event::None,
        "the message is gone: its continuation is now spurious"
    );

    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 100, &[0; 57]), 0),
        Event::None
    );
    assert_eq!(
        reply(transport.receive(&init_packet(1, 0x01, 0, &[]), 0)),
        error(1, 0x04)
    );
}

/// INIT in the middle of a message on the same channel resynchronizes instead of failing
/// (§11.2.5.3).
#[test]
fn init_resynchronizes_a_message_in_progress() {
    let mut transport = with_channels::<1024>(1);
    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 100, &[0; 57]), 0),
        Event::None
    );
    let (cid, command, _) = reply(transport.receive(&init_packet(1, 0x06, 8, &NONCE), 0));
    assert_eq!((cid, command), (1, Command::Init));
    assert_eq!(
        transport.receive(&cont_packet(1, 0, &[0; 43]), 0),
        Event::None
    );
}

/// Another channel's request while a message is assembled gets ERR_CHANNEL_BUSY and the
/// message still completes (§11.2.5.1).
#[test]
fn another_channel_is_busy_while_a_message_is_assembled() {
    let mut transport = with_channels::<1024>(2);
    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 60, &[7; 57]), 0),
        Event::None
    );
    assert_eq!(
        reply(transport.receive(&init_packet(2, 0x01, 0, &[]), 1)),
        error(2, 0x06)
    );
    assert_eq!(
        reply(transport.receive(&cont_packet(1, 0, &[7; 3]), 2)),
        (1, Command::Ping, vec![7; 60])
    );
}

/// Continuation packets without a message in progress are ignored (§11.2.5.4).
#[test]
fn spurious_continuation_packets_are_ignored() {
    let mut transport = with_channels::<1024>(1);
    for seq in [0, 5, 0x7F] {
        assert_eq!(
            transport.receive(&cont_packet(1, seq, &[1; 59]), 0),
            Event::None
        );
    }
}

/// A message whose next packet is late is abandoned: the late continuation gets
/// ERR_MSG_TIMEOUT, a packet just in time continues it, and a clock that went backwards counts
/// as late (§11.2.5.2).
#[test]
fn a_late_packet_times_the_message_out() {
    let mut transport = with_channels::<1024>(1);
    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 200, &[0; 57]), 1000),
        Event::None
    );
    assert_eq!(
        transport.receive(&cont_packet(1, 0, &[0; 59]), 1000 + PACKET_TIMEOUT_MS - 1),
        Event::None
    );
    // Exactly PACKET_TIMEOUT_MS after the previous packet is already late.
    assert_eq!(
        reply(transport.receive(&cont_packet(1, 1, &[0; 59]), 1099 + PACKET_TIMEOUT_MS)),
        error(1, 0x05)
    );

    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 200, &[0; 57]), 5000),
        Event::None
    );
    assert_eq!(
        reply(transport.receive(&cont_packet(1, 0, &[0; 59]), 4999)),
        error(1, 0x05)
    );
}

/// After a timeout the device is idle again: another channel's request is served, not refused
/// as busy (§11.2.5.2).
#[test]
fn a_timed_out_message_frees_the_device() {
    let mut transport = with_channels::<1024>(2);
    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 200, &[0; 57]), 0),
        Event::None
    );
    assert_eq!(
        reply(transport.receive(&init_packet(2, 0x01, 0, &[]), PACKET_TIMEOUT_MS)),
        (2, Command::Ping, Vec::new())
    );
}

/// Unknown commands, the optional LOCK and WINK, and the response-only KEEPALIVE and ERROR are
/// ERR_INVALID_CMD (§11.2.9).
#[test]
fn unsupported_commands_are_invalid_cmd() {
    let mut transport = with_channels::<1024>(1);
    for cmd in [0x00, 0x02, 0x04, 0x08, 0x3B, 0x3F, 0x40, 0x7F] {
        assert_eq!(
            reply(transport.receive(&init_packet(1, cmd, 0, &[]), 0)),
            error(1, 0x01),
            "command {cmd:#04x}"
        );
    }
}

/// Unused bytes SHOULD be zero but need not be (§11.2.4): padding is not payload.
#[test]
fn nonzero_padding_is_not_payload() {
    let mut transport = with_channels::<1024>(1);
    let mut packet = init_packet(1, 0x01, 2, &[0xAA, 0xBB]);
    packet[9..].fill(0xFF);
    assert_eq!(
        reply(transport.receive(&packet, 0)),
        (1, Command::Ping, vec![0xAA, 0xBB])
    );
}

/// Command codes are the ones of §11.2.9; unknown codes come back as the error value.
#[test]
fn command_codes_follow_the_specification() {
    let table = [
        (0x01, Command::Ping),
        (0x03, Command::Msg),
        (0x04, Command::Lock),
        (0x06, Command::Init),
        (0x08, Command::Wink),
        (0x10, Command::Cbor),
        (0x11, Command::Cancel),
        (0x3B, Command::Keepalive),
        (0x3F, Command::Error),
    ];
    for (code, command) in table {
        assert_eq!(Command::try_from(code), Ok(command));
        assert_eq!(command as u8, code);
    }
    assert_eq!(Command::try_from(0x02), Err(UnknownCommand(0x02)));
    assert_eq!(ErrorCode::InvalidChannel as u8, 0x0B);
    assert_eq!(ErrorCode::LockRequired as u8, 0x0A);
}

/// An empty response is one initialization packet with BCNT 0 and zero padding (§11.2.4).
#[test]
fn an_empty_response_is_one_zero_padded_packet() {
    let frames: Vec<Report> = Frames::new(0x0102_0304, Command::Ping, &[])
        .expect("fits")
        .collect();
    let mut expected = [0u8; 64];
    expected[..7].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x81, 0x00, 0x00]);
    assert_eq!(frames, vec![expected]);
}

/// A response is split at 57 bytes, then 59 per continuation packet with ascending sequence
/// numbers (§11.2.4).
#[test]
fn responses_split_at_the_packet_boundaries() {
    let payload: Vec<u8> = (0..120u8).collect();
    let frames: Vec<Report> = Frames::new(9, Command::Cbor, &payload)
        .expect("fits")
        .collect();
    let mut first = [0u8; 64];
    first[..7].copy_from_slice(&[0, 0, 0, 9, 0x90, 0x00, 120]);
    first[7..].copy_from_slice(&payload[..57]);
    let mut second = [0u8; 64];
    second[..5].copy_from_slice(&[0, 0, 0, 9, 0x00]);
    second[5..].copy_from_slice(&payload[57..116]);
    let mut third = [0u8; 64];
    third[..5].copy_from_slice(&[0, 0, 0, 9, 0x01]);
    third[5..9].copy_from_slice(&payload[116..]);
    assert_eq!(frames, vec![first, second, third]);

    assert_eq!(
        Frames::new(9, Command::Cbor, &[0; 57])
            .expect("fits")
            .count(),
        1
    );
    assert_eq!(
        Frames::new(9, Command::Cbor, &[0; 58])
            .expect("fits")
            .count(),
        2
    );
}

/// The largest response takes 129 packets ending with sequence 127; one byte more cannot be
/// framed.
#[test]
fn the_largest_response_ends_at_sequence_127() {
    let payload = vec![0x5A; 7609];
    let frames: Vec<Report> = Frames::new(1, Command::Cbor, &payload)
        .expect("fits")
        .collect();
    assert_eq!(frames.len(), 129);
    assert_eq!(frames[128][4], 0x7F);
    assert_eq!(&frames[128][5..], &[0x5A; 59][..]);
    assert_eq!(
        Frames::new(1, Command::Cbor, &[0; 7610]).map(Iterator::count),
        Err(TooLong)
    );
}

/// A keepalive is CMD 0x3B with BCNT 1 and the status byte (§11.2.9.1.7).
#[test]
fn keepalive_carries_the_status() {
    let mut expected = [0u8; 64];
    expected[..8].copy_from_slice(&[0, 0, 0, 7, 0xBB, 0x00, 0x01, 0x02]);
    assert_eq!(keepalive(7, KeepaliveStatus::UpNeeded), expected);
    assert_eq!(keepalive(7, KeepaliveStatus::Processing)[7], 0x01);
}

/// Request bytes (possibly PIN/UV material) leave the buffer when the request ends: answered,
/// aborted by INIT, broken by a sequence error, timed out, or echoed by PING.
#[test]
fn request_bytes_are_wiped_when_the_request_ends() {
    let secret = [0x5Au8; 57];
    let wiped = |transport: &Transport<1024>| transport.buffer.iter().all(|&byte| byte == 0);

    let mut answered = with_channels::<1024>(1);
    assert!(matches!(
        answered.receive(&init_packet(1, 0x10, 57, &secret), 0),
        Event::Request { .. }
    ));
    answered.finish();
    assert!(wiped(&answered), "finished request");

    let mut aborted = with_channels::<1024>(1);
    assert!(matches!(
        aborted.receive(&init_packet(1, 0x10, 57, &secret), 0),
        Event::Request { .. }
    ));
    reply(aborted.receive(&init_packet(1, 0x06, 8, &NONCE), 0));
    assert!(
        aborted.buffer[NONCE.len()..].iter().all(|&byte| byte == 0),
        "INIT abort"
    );

    let mut broken = with_channels::<1024>(1);
    assert_eq!(
        broken.receive(&init_packet(1, 0x10, 200, &secret), 0),
        Event::None
    );
    reply(broken.receive(&cont_packet(1, 3, &[0; 59]), 0));
    assert!(wiped(&broken), "sequence error");

    let mut stalled = with_channels::<1024>(1);
    assert_eq!(
        stalled.receive(&init_packet(1, 0x10, 200, &secret), 0),
        Event::None
    );
    reply(stalled.poll(PACKET_TIMEOUT_MS));
    assert!(wiped(&stalled), "timeout");

    let mut echoed = with_channels::<1024>(1);
    reply(echoed.receive(&init_packet(1, 0x01, 57, &secret), 0));
    assert_eq!(echoed.poll(0), Event::None);
    assert!(wiped(&echoed), "PING echo, wiped on the next call");
}

/// An unknown command on channel 0, the broadcast channel or an unallocated channel is
/// ERR_INVALID_CHANNEL like any other command there: the channel is checked first (§11.2.3).
#[test]
fn unknown_commands_on_invalid_channels_are_invalid_channel() {
    let mut transport = with_channels::<1024>(1);
    for cid in [0, BROADCAST_CID, 5] {
        assert_eq!(
            reply(transport.receive(&init_packet(cid, 0x02, 0, &[]), 0)),
            error(cid, 0x0B),
            "channel {cid:#x}"
        );
    }
}

/// A stalled message times out at its deadline without another report: polling gives the
/// channel ERR_MSG_TIMEOUT and frees the device (§11.2.5.2).
#[test]
fn polling_times_out_a_stalled_message() {
    let mut transport = with_channels::<1024>(1);
    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 200, &[0; 57]), 1000),
        Event::None
    );
    assert_eq!(transport.poll(1000 + PACKET_TIMEOUT_MS - 1), Event::None);
    assert_eq!(
        reply(transport.poll(1000 + PACKET_TIMEOUT_MS)),
        error(1, 0x05)
    );
    assert_eq!(transport.poll(5000), Event::None, "reported once");
    assert_eq!(
        transport.receive(&cont_packet(1, 0, &[0; 59]), 5000),
        Event::None,
        "its continuation is now spurious"
    );
}

/// CANCEL is defined with BCNT 0 (§11.2.9.1.5): one with a payload cancels nothing, breaks no
/// message and, like every CANCEL, is not answered.
#[test]
fn cancel_with_a_payload_is_ignored() {
    let mut transport = with_channels::<1024>(1);
    cbor_request(&mut transport, 1);
    assert_eq!(
        transport.receive(&init_packet(1, 0x11, 1, &[0]), 0),
        Event::None
    );
    assert_eq!(transport.active(), Some(1));
    transport.finish();

    assert_eq!(
        transport.receive(&init_packet(1, 0x01, 60, &[3; 57]), 0),
        Event::None
    );
    assert_eq!(
        transport.receive(&init_packet(1, 0x11, 2, &[0, 0]), 0),
        Event::None
    );
    assert_eq!(
        reply(transport.receive(&cont_packet(1, 0, &[3; 3]), 0)),
        (1, Command::Ping, vec![3; 60])
    );
}
