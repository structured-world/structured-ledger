//! CTAPHID: the USB HID framing of CTAP (CTAP 2.2, §11.2 "USB Human Interface Device").
//!
//! [`Transport`] turns 64-byte HID reports into requests and transport-level replies, keeps the
//! channel and busy state, and never allocates: the message buffer is a const-generic array.
//! [`Frames`] splits a response into reports, [`keepalive`] builds a keepalive report.
//!
//! # Examples
//!
//! ```
//! use structured_passkeys_ctap::ctaphid::{
//!     BROADCAST_CID, Command, DeviceInfo, Event, Frames, REPORT_SIZE, Transport,
//! };
//!
//! let info = DeviceInfo { version: [0, 1, 0], cbor: true, msg: false };
//! let mut transport = Transport::<1024>::new(info);
//! // CTAPHID_INIT on the broadcast channel with an 8-byte nonce.
//! let mut report = [0u8; REPORT_SIZE];
//! report[..4].copy_from_slice(&BROADCAST_CID.to_be_bytes());
//! report[4] = 0x86;
//! report[6] = 8;
//! report[7..15].copy_from_slice(b"nonce123");
//! let Event::Reply { cid, command, payload } = transport.receive(&report, 0) else {
//!     panic!("INIT is answered by the transport");
//! };
//! assert_eq!((cid, command, payload.len()), (BROADCAST_CID, Command::Init, 17));
//! let reports: Vec<_> = Frames::new(cid, command, payload).expect("fits").collect();
//! assert_eq!(reports.len(), 1);
//! ```

use zeroize::Zeroize;

/// Size of a CTAPHID report in bytes (§11.2.8.1, full-speed endpoints).
pub const REPORT_SIZE: usize = 64;

/// One HID report.
pub type Report = [u8; REPORT_SIZE];

/// Channel used to allocate channels (§11.2.3).
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;

/// Largest payload the framing can carry: `64 - 7 + 128 * (64 - 5)` (§11.2.4).
pub const MAX_MESSAGE_SIZE: usize = INIT_DATA + 128 * CONT_DATA;

/// Time allowed between two packets of one request before it is abandoned (§11.2.5.2 requires a
/// timeout without fixing it; hosts send the packets of a message back to back).
pub const PACKET_TIMEOUT_MS: u64 = 100;

/// CTAPHID protocol version reported by INIT (§11.2.9.1.3).
const PROTOCOL_VERSION: u8 = 2;

/// Payload bytes of an initialization packet: CID (4), CMD (1), BCNT (2) precede them.
const INIT_DATA: usize = REPORT_SIZE - 7;

/// Payload bytes of a continuation packet: CID (4), SEQ (1) precede them.
const CONT_DATA: usize = REPORT_SIZE - 5;

/// Highest sequence number of a continuation packet (§11.2.4).
const MAX_SEQ: u8 = 0x7F;

/// Bit 7 of the fifth byte tells an initialization packet from a continuation packet (§11.2.4).
const INIT_BIT: u8 = 0x80;

/// INIT request nonce length and response length (§11.2.9.1.3).
const NONCE_LEN: usize = 8;
const INIT_RESPONSE_LEN: usize = 17;

/// CTAPHID command codes (§11.2.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Echo (§11.2.9.1.4).
    Ping = 0x01,
    /// CTAP1/U2F message (§11.2.9.1.1).
    Msg = 0x03,
    /// Channel lock, optional (§11.2.9.2.2).
    Lock = 0x04,
    /// Channel allocation and resynchronization (§11.2.9.1.3).
    Init = 0x06,
    /// Identify the device, optional (§11.2.9.2.1).
    Wink = 0x08,
    /// CTAP2 CBOR message (§11.2.9.1.2).
    Cbor = 0x10,
    /// Cancel the request being processed (§11.2.9.1.5).
    Cancel = 0x11,
    /// Progress of a request, device to host only (§11.2.9.1.7).
    Keepalive = 0x3B,
    /// Transport error, device to host only (§11.2.9.1.6).
    Error = 0x3F,
}

/// A command code that §11.2.9 does not define.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownCommand(pub u8);

impl TryFrom<u8> for Command {
    type Error = UnknownCommand;

    /// Reads a command code without the initialization-packet bit.
    fn try_from(code: u8) -> Result<Self, UnknownCommand> {
        Ok(match code {
            0x01 => Command::Ping,
            0x03 => Command::Msg,
            0x04 => Command::Lock,
            0x06 => Command::Init,
            0x08 => Command::Wink,
            0x10 => Command::Cbor,
            0x11 => Command::Cancel,
            0x3B => Command::Keepalive,
            0x3F => Command::Error,
            other => return Err(UnknownCommand(other)),
        })
    }
}

/// CTAPHID error codes (§11.2.9.1.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    /// The command is invalid or not implemented.
    InvalidCmd = 0x01,
    /// A parameter is invalid.
    InvalidPar = 0x02,
    /// BCNT is invalid for the request.
    InvalidLen = 0x03,
    /// The sequence number does not match.
    InvalidSeq = 0x04,
    /// The message timed out.
    MsgTimeout = 0x05,
    /// The device is busy with another channel.
    ChannelBusy = 0x06,
    /// The command requires a channel lock.
    LockRequired = 0x0A,
    /// The channel is not valid.
    InvalidChannel = 0x0B,
    /// Unspecified error.
    Other = 0x7F,
}

/// Status carried by a keepalive (§11.2.9.1.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeepaliveStatus {
    /// Still processing the request.
    Processing = 1,
    /// Waiting for user presence.
    UpNeeded = 2,
}

/// What INIT reports about the device (§11.2.9.1.3). The capability flags are derived from it, so
/// they always match the commands the transport accepts; WINK is never claimed, since it is not
/// implemented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Major, minor and build device version numbers (vendor defined).
    pub version: [u8; 3],
    /// `CTAPHID_CBOR` requests are accepted and CAPABILITY_CBOR is reported.
    pub cbor: bool,
    /// `CTAPHID_MSG` requests are accepted; otherwise CAPABILITY_NMSG is reported.
    pub msg: bool,
}

impl DeviceInfo {
    /// The capability byte of the INIT response (§11.2.9.1.3).
    const fn capabilities(&self) -> u8 {
        let cbor = if self.cbor { CAPABILITY_CBOR } else { 0 };
        let nmsg = if self.msg { 0 } else { CAPABILITY_NMSG };
        cbor | nmsg
    }

    /// Whether requests of `command` are handed to the CTAP layer.
    const fn accepts(&self, command: Command) -> bool {
        match command {
            Command::Cbor => self.cbor,
            Command::Msg => self.msg,
            Command::Ping | Command::Init => true,
            Command::Lock
            | Command::Wink
            | Command::Cancel
            | Command::Keepalive
            | Command::Error => false,
        }
    }
}

/// The device implements `CTAPHID_CBOR` (§11.2.9.1.3).
const CAPABILITY_CBOR: u8 = 0x04;
/// The device does NOT implement `CTAPHID_MSG` (§11.2.9.1.3).
const CAPABILITY_NMSG: u8 = 0x08;

/// What one received report asks the caller to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// Nothing to send: a packet of an incomplete request, or one that is ignored.
    None,
    /// A transport-level response (INIT, PING echo, ERROR) to send now with [`Frames`]; it ends
    /// its transaction.
    Reply {
        /// Channel to answer on.
        cid: u32,
        /// Command of the response.
        command: Command,
        /// Response payload.
        payload: &'a [u8],
    },
    /// A complete `CTAPHID_MSG` or `CTAPHID_CBOR` request for the CTAP layer. The device stays
    /// busy for this channel until [`Transport::finish`].
    Request {
        /// Channel of the request.
        cid: u32,
        /// `Command::Msg` or `Command::Cbor`.
        command: Command,
        /// Request payload.
        payload: &'a [u8],
    },
    /// `CTAPHID_CANCEL` for the request being processed on `cid`: the CTAP layer ends it with
    /// `CTAP2_ERR_KEEPALIVE_CANCEL` (§11.2.9.1.5). Never answered by itself.
    Cancel {
        /// Channel of the cancelled request.
        cid: u32,
    },
}

/// Transaction state (§11.2.5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Idle,
    /// Receiving the continuation packets of a request.
    Assembling {
        cid: u32,
        command: Command,
        len: usize,
        filled: usize,
        next_seq: u8,
        last_packet_ms: u64,
    },
    /// A request handed to the CTAP layer and not answered yet.
    Processing {
        cid: u32,
    },
}

/// CTAPHID receiver: reassembles requests up to `N` bytes and keeps channel and busy state.
///
/// `N` is the device buffer, reported as `maxMsgSize`; it is at least one report's payload and
/// at most [`MAX_MESSAGE_SIZE`].
pub struct Transport<const N: usize> {
    buffer: [u8; N],
    /// Leading bytes of `buffer` that may still hold request data.
    dirty: usize,
    reply: [u8; INIT_RESPONSE_LEN],
    state: State,
    last_cid: u32,
    info: DeviceInfo,
}

impl<const N: usize> Drop for Transport<N> {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl<const N: usize> Transport<N> {
    const SIZE_IN_RANGE: () = assert!(N >= INIT_DATA && N <= MAX_MESSAGE_SIZE);

    /// Creates an idle transport with no channel allocated.
    pub const fn new(info: DeviceInfo) -> Self {
        let () = Self::SIZE_IN_RANGE;
        Self {
            buffer: [0; N],
            dirty: 0,
            reply: [0; INIT_RESPONSE_LEN],
            state: State::Idle,
            last_cid: 0,
            info,
        }
    }

    /// Zeroes the request bytes held in the buffer: a request can carry PIN/UV material.
    fn wipe(&mut self) {
        self.buffer[..self.dirty].zeroize();
        self.dirty = 0;
    }

    /// Ends the current transaction and wipes its data.
    fn reset(&mut self) {
        self.state = State::Idle;
        self.wipe();
    }

    /// Records that the first `end` bytes of the buffer now hold request data.
    fn mark_dirty(&mut self, end: usize) {
        self.dirty = self.dirty.max(end);
    }

    /// A broken internal invariant: the transaction is dropped and the channel told so.
    fn broken(&mut self, cid: u32) -> Event<'_> {
        self.reset();
        self.error(cid, ErrorCode::Other)
    }

    /// Abandons a message whose next packet is late (§11.2.5.2) and returns its channel.
    fn expire(&mut self, now_ms: u64) -> Option<u32> {
        let State::Assembling {
            cid,
            last_packet_ms,
            ..
        } = self.state
        else {
            return None;
        };
        // A clock that went backwards abandons the message too: its age is unknown.
        let expired = now_ms
            .checked_sub(last_packet_ms)
            .is_none_or(|age| age >= PACKET_TIMEOUT_MS);
        if !expired {
            return None;
        }
        self.reset();
        Some(cid)
    }

    /// Largest request accepted, in bytes.
    pub const fn max_message_size(&self) -> usize {
        N
    }

    /// Channel of the request handed out by [`Event::Request`] and not finished yet; `None`
    /// once it was answered, aborted by INIT, or never existed.
    pub fn active(&self) -> Option<u32> {
        match self.state {
            State::Processing { cid } => Some(cid),
            _ => None,
        }
    }

    /// Marks the request of [`Transport::active`] as answered; the device becomes idle and the
    /// request bytes are wiped.
    pub fn finish(&mut self) {
        if matches!(self.state, State::Processing { .. }) {
            self.reset();
        }
    }

    /// Called by the device loop without a report, at least as often as keepalives are sent:
    /// times out a stalled message at its deadline (§11.2.5.2) and wipes the data of a reply
    /// already sent.
    pub fn poll(&mut self, now_ms: u64) -> Event<'_> {
        if self.state == State::Idle {
            self.wipe();
        }
        match self.expire(now_ms) {
            Some(cid) => self.error(cid, ErrorCode::MsgTimeout),
            None => Event::None,
        }
    }

    /// Handles one report received at `now_ms` (a monotonic millisecond clock).
    pub fn receive(&mut self, report: &Report, now_ms: u64) -> Event<'_> {
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        if self.state == State::Idle {
            // The previous reply (a PING echo) has been sent by now.
            self.wipe();
        }
        // §11.2.5.2: the late packet of an abandoned message learns why.
        if self.expire(now_ms) == Some(cid) && report[4] & INIT_BIT == 0 {
            return self.error(cid, ErrorCode::MsgTimeout);
        }
        if report[4] & INIT_BIT == 0 {
            self.continuation(cid, report, now_ms)
        } else {
            self.initialization(cid, report, now_ms)
        }
    }

    fn continuation(&mut self, cid: u32, report: &Report, now_ms: u64) -> Event<'_> {
        let State::Assembling {
            cid: active,
            command,
            len,
            filled,
            next_seq,
            ..
        } = self.state
        else {
            // §11.2.5.4: spurious continuation packets are ignored.
            return Event::None;
        };
        if cid != active {
            // §11.2.5.1: another channel during a transaction is busy; a continuation packet is
            // not a request, so it is only dropped.
            return Event::None;
        }
        let seq = report[4];
        if seq != next_seq {
            self.reset();
            return self.error(cid, ErrorCode::InvalidSeq);
        }
        // `filled < len <= N` while assembling; a violation drops the message instead of
        // wrapping or panicking on host-driven offsets.
        let Some(remaining) = len.checked_sub(filled) else {
            return self.broken(cid);
        };
        let take = remaining.min(CONT_DATA);
        let Some(end) = filled.checked_add(take) else {
            return self.broken(cid);
        };
        let (Some(target), Some(source)) =
            (self.buffer.get_mut(filled..end), report.get(5..5 + take))
        else {
            return self.broken(cid);
        };
        target.copy_from_slice(source);
        self.mark_dirty(end);
        if end < len {
            // A message of at most N <= MAX_MESSAGE_SIZE bytes ends by sequence MAX_SEQ.
            let Some(next_seq) = seq.checked_add(1).filter(|next| *next <= MAX_SEQ) else {
                return self.broken(cid);
            };
            self.state = State::Assembling {
                cid,
                command,
                len,
                filled: end,
                next_seq,
                last_packet_ms: now_ms,
            };
            return Event::None;
        }
        self.state = State::Idle;
        self.complete(cid, command, len)
    }

    fn initialization(&mut self, cid: u32, report: &Report, now_ms: u64) -> Event<'_> {
        let code = report[4] & !INIT_BIT;
        let len = usize::from(u16::from_be_bytes([report[5], report[6]]));
        let command = Command::try_from(code);

        // §11.2.9.1.5 defines CANCEL with BCNT 0; one with a payload is not that request and is
        // ignored in every state. No CANCEL is ever answered.
        let cancel = command == Ok(Command::Cancel);
        if cancel && len != 0 {
            return Event::None;
        }

        match self.state {
            State::Processing { cid: active } if cid == active => {
                return match command {
                    Ok(Command::Cancel) => Event::Cancel { cid },
                    // §11.2.5.3: INIT on the active channel aborts its transaction.
                    Ok(Command::Init) => {
                        self.reset();
                        self.start(cid, Command::Init, len, report, now_ms)
                    }
                    // The channel's own request is still being processed.
                    _ => self.error(cid, ErrorCode::ChannelBusy),
                };
            }
            State::Assembling { cid: active, .. } if cid == active => {
                // §11.2.5.3: INIT resynchronizes the channel; CANCEL gives the message up; any
                // other initialization packet breaks the message being assembled.
                self.reset();
                match command {
                    Ok(Command::Init) => {}
                    Ok(Command::Cancel) => return Event::None,
                    _ => return self.error(cid, ErrorCode::InvalidSeq),
                }
            }
            State::Processing { .. } | State::Assembling { .. } => {
                // §11.2.9.1.5: CANCEL on a non-active channel is ignored.
                if cancel {
                    return Event::None;
                }
                // §11.2.5.1: a request from another channel fails immediately.
                return self.error(cid, ErrorCode::ChannelBusy);
            }
            State::Idle => {}
        }

        // §11.2.9.1.5: CANCEL with nothing to cancel is ignored, on any channel.
        if cancel {
            return Event::None;
        }
        // §11.2.3: channel 0 is reserved, the broadcast channel only allocates, and any other
        // channel must have been allocated. Checked before the command, so an unknown command
        // there is still an invalid channel.
        let valid_channel = match cid {
            0 => false,
            BROADCAST_CID => command == Ok(Command::Init),
            _ => cid <= self.last_cid,
        };
        if !valid_channel {
            return self.error(cid, ErrorCode::InvalidChannel);
        }
        match command {
            Ok(command) => self.start(cid, command, len, report, now_ms),
            Err(UnknownCommand(_)) => self.error(cid, ErrorCode::InvalidCmd),
        }
    }

    /// Starts or completes a request on an idle device, on a channel already checked.
    fn start(
        &mut self,
        cid: u32,
        command: Command,
        len: usize,
        report: &Report,
        now_ms: u64,
    ) -> Event<'_> {
        // Only what INIT advertises is accepted: optional commands not implemented, device-to-host
        // commands, CANCEL (handled before any request starts) and a disabled MSG or CBOR are not.
        if !self.info.accepts(command) {
            return self.error(cid, ErrorCode::InvalidCmd);
        }
        if command == Command::Init && len != NONCE_LEN {
            return self.error(cid, ErrorCode::InvalidLen);
        }
        if len > N {
            return self.error(cid, ErrorCode::InvalidLen);
        }
        // At most INIT_DATA bytes, which N is at least.
        let take = len.min(INIT_DATA);
        self.buffer[..take].copy_from_slice(&report[7..7 + take]);
        self.mark_dirty(take);
        if take < len {
            self.state = State::Assembling {
                cid,
                command,
                len,
                filled: take,
                next_seq: 0,
                last_packet_ms: now_ms,
            };
            return Event::None;
        }
        self.complete(cid, command, len)
    }

    /// Answers or hands out a fully received request of `len` bytes in the buffer.
    fn complete(&mut self, cid: u32, command: Command, len: usize) -> Event<'_> {
        match command {
            Command::Init => self.init(cid),
            Command::Ping => Event::Reply {
                cid,
                command: Command::Ping,
                payload: &self.buffer[..len],
            },
            Command::Msg | Command::Cbor => {
                self.state = State::Processing { cid };
                Event::Request {
                    cid,
                    command,
                    payload: &self.buffer[..len],
                }
            }
            // `start` lets only the four commands above assemble.
            Command::Lock
            | Command::Wink
            | Command::Cancel
            | Command::Keepalive
            | Command::Error => self.error(cid, ErrorCode::InvalidCmd),
        }
    }

    /// Answers INIT: allocates a channel on the broadcast channel, or confirms the channel it was
    /// received on (§11.2.9.1.3).
    fn init(&mut self, cid: u32) -> Event<'_> {
        let channel = if cid == BROADCAST_CID {
            match self.last_cid.checked_add(1) {
                Some(next) if next != BROADCAST_CID => {
                    self.last_cid = next;
                    next
                }
                // Every channel identifier is taken; only a restart frees them.
                _ => return self.error(cid, ErrorCode::Other),
            }
        } else {
            cid
        };
        self.reply[..NONCE_LEN].copy_from_slice(&self.buffer[..NONCE_LEN]);
        self.reply[8..12].copy_from_slice(&channel.to_be_bytes());
        self.reply[12] = PROTOCOL_VERSION;
        self.reply[13..16].copy_from_slice(&self.info.version);
        self.reply[16] = self.info.capabilities();
        Event::Reply {
            cid,
            command: Command::Init,
            payload: &self.reply,
        }
    }

    fn error(&mut self, cid: u32, code: ErrorCode) -> Event<'_> {
        self.reply[0] = code as u8;
        Event::Reply {
            cid,
            command: Command::Error,
            payload: &self.reply[..1],
        }
    }
}

/// A response payload too long for CTAPHID framing ([`MAX_MESSAGE_SIZE`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLong;

/// Reports of one response message, in order (§11.2.4); unused bytes are zero.
#[derive(Debug)]
pub struct Frames<'a> {
    cid: u32,
    command: Command,
    payload: &'a [u8],
    offset: usize,
    seq: Option<u8>,
}

impl<'a> Frames<'a> {
    /// Splits `payload` into the reports of a `command` response on `cid`.
    ///
    /// # Errors
    ///
    /// [`TooLong`] when the payload exceeds [`MAX_MESSAGE_SIZE`].
    pub fn new(cid: u32, command: Command, payload: &'a [u8]) -> Result<Self, TooLong> {
        if payload.len() > MAX_MESSAGE_SIZE {
            return Err(TooLong);
        }
        Ok(Self {
            cid,
            command,
            payload,
            offset: 0,
            seq: None,
        })
    }
}

impl Iterator for Frames<'_> {
    type Item = Report;

    fn next(&mut self) -> Option<Report> {
        let mut report = [0u8; REPORT_SIZE];
        report[..4].copy_from_slice(&self.cid.to_be_bytes());
        match self.seq {
            None => {
                report[4] = self.command as u8 | INIT_BIT;
                // `new` bounds the payload by MAX_MESSAGE_SIZE, which fits in BCNT.
                let len = self.payload.len() as u16;
                report[5..7].copy_from_slice(&len.to_be_bytes());
                let take = self.payload.len().min(INIT_DATA);
                report[7..7 + take].copy_from_slice(&self.payload[..take]);
                self.offset = take;
                self.seq = Some(0);
            }
            Some(seq) => {
                if self.offset >= self.payload.len() {
                    return None;
                }
                debug_assert!(seq <= MAX_SEQ, "payload bounded by MAX_MESSAGE_SIZE");
                report[4] = seq;
                let take = (self.payload.len() - self.offset).min(CONT_DATA);
                let end = self
                    .offset
                    .checked_add(take)
                    .expect("offset + take stays within the payload length");
                report[5..5 + take].copy_from_slice(&self.payload[self.offset..end]);
                self.offset = end;
                // A payload of at most MAX_MESSAGE_SIZE ends by sequence MAX_SEQ (0x7F), so the
                // next value is at most 0x80 and is never written: the payload is exhausted.
                self.seq = Some(seq.checked_add(1).expect("sequence is at most MAX_SEQ"));
            }
        }
        Some(report)
    }
}

/// The keepalive report sent on `cid` while a request waits (§11.2.9.1.7).
pub fn keepalive(cid: u32, status: KeepaliveStatus) -> Report {
    let mut report = [0u8; REPORT_SIZE];
    report[..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = Command::Keepalive as u8 | INIT_BIT;
    report[6] = 1;
    report[7] = status as u8;
    report
}

#[cfg(test)]
mod tests;
