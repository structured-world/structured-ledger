//! The FIDO HID interface: the application's own class for the C SDK's USB stack, in place of the
//! C SDK's `usbd_ledger_hid_u2f.c` and its CTAPHID (`lib_u2f`).
//!
//! The stack finds the class through the one symbol it references, `USBD_LEDGER_HID_U2F_class_info`;
//! defining it here keeps the linker from taking the C class out of the SDK archive. The class
//! declares a plain HID interface with the FIDO report descriptor (CTAP 2.2 §11.2.8) and moves raw
//! 64-byte reports between its endpoints and the core crate's [`Transport`], which owns the
//! protocol: framing, channels, busy state, timeouts and keepalives.

use core::cell::{Cell, RefCell, UnsafeCell};
use core::ffi::c_void;
use core::mem::MaybeUninit;

use structured_passkeys_ctap::ctap2::{Authenticator, MaxMsgSize, Settings};
use structured_passkeys_ctap::ctaphid::{
    DeviceInfo, Event, MAX_MESSAGE_SIZE, REPORT_SIZE, Report, Transport,
};

/// Interval of the OS ticker events the main loop forwards to [`tick`]; the transport clock
/// advances by this much per tick.
pub const TICK_MS: u64 = 100;

/// `USBD_StatusTypeDef` (`usbd_def.h`): one byte, as the SDK compiles C with `-fshort-enums`.
type UsbdStatus = u8;
const USBD_OK: UsbdStatus = 0;
const USBD_FAIL: UsbdStatus = 3;

/// `usbd_ledger_class_mask_e::USBD_LEDGER_CLASS_HID_U2F` (`usbd_ledger.h`).
const CLASS_HID_U2F: u8 = 0x04;

/// Endpoints of the interface: interrupt IN 0x81 and OUT 0x01, one report per transfer
/// (§11.2.8.1).
const EP_IN: u8 = 0x81;
const EP_OUT: u8 = 0x01;
const EP_TYPE_INTERRUPT: u8 = 0x03;
const REPORT_LEN: u8 = REPORT_SIZE as u8;

/// The FIDO HID report descriptor (§11.2.8.2): usage page 0xF1D0, usage CTAPHID, one 64-byte input
/// and one 64-byte output report without report IDs.
#[rustfmt::skip] // One item per line, as the descriptor tables lay them out.
const REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (CTAPHID)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, REPORT_LEN, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, REPORT_LEN, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

const HID_DESCRIPTOR_TYPE: u8 = 0x21;
const REPORT_DESCRIPTOR_TYPE: u8 = 0x22;
/// Offset of the HID descriptor in [`DESCRIPTORS`], after the interface descriptor.
const HID_DESCRIPTOR_AT: usize = 9;
const HID_DESCRIPTOR_LEN: usize = 9;

/// Interface, HID and endpoint descriptors (USB 2.0 §9.6.5, §9.6.6; HID 1.11 §6.2.1). The
/// interface is HID with subclass and protocol 0x00: the FIDO interface is no boot device
/// (§11.2.8.1). The stack writes the interface number into byte 2.
#[rustfmt::skip] // One descriptor per line.
const DESCRIPTORS: [u8; 32] = [
    // Interface: length, type, number (set by the stack), alternate setting, 2 endpoints,
    // class HID, subclass 0, protocol 0, string index of the product name.
    9, 0x04, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x02,
    // HID 1.11, not localized, one report descriptor.
    9, HID_DESCRIPTOR_TYPE, 0x11, 0x01, 0x00, 0x01, REPORT_DESCRIPTOR_TYPE,
    REPORT_DESCRIPTOR.len() as u8, 0x00,
    // Interrupt IN endpoint, 64 bytes, polled every frame.
    7, 0x05, EP_IN, EP_TYPE_INTERRUPT, REPORT_LEN, 0x00, 0x01,
    // Interrupt OUT endpoint, 64 bytes, polled every frame.
    7, 0x05, EP_OUT, EP_TYPE_INTERRUPT, REPORT_LEN, 0x00, 0x01,
];

/// `USBD_SetupReqTypedef` (`usbd_def.h`).
#[repr(C)]
struct SetupRequest {
    bm_request: u8,
    b_request: u8,
    w_value: u16,
    w_index: u16,
    w_length: u16,
}

/// `usbd_end_point_info_t` (`usbd_ledger_types.h`).
#[repr(C)]
struct EndPointInfo {
    ep_in_addr: u8,
    ep_in_size: u16,
    ep_out_addr: u8,
    ep_out_size: u16,
    ep_type: u8,
}

type Init = unsafe extern "C" fn(*mut c_void, *mut c_void) -> UsbdStatus;
type Setup = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut SetupRequest) -> UsbdStatus;
type DataIn = unsafe extern "C" fn(*mut c_void, *mut c_void, u8) -> UsbdStatus;
type DataOut = unsafe extern "C" fn(*mut c_void, *mut c_void, u8, *mut u8, u16) -> UsbdStatus;
type SendPacket =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u8, *const u8, u16, u32) -> UsbdStatus;

/// `usbd_class_info_t` (`usbd_ledger_types.h`). The stack passes every function pointer through
/// `PIC()` before calling it, and skips the optional ones that are null.
#[repr(C)]
pub struct ClassInfo {
    class_type: u8,
    end_point: *const EndPointInfo,
    init: Option<Init>,
    de_init: Option<Init>,
    setup: Option<Setup>,
    ep0_rx_ready: Option<Init>,
    data_in: Option<DataIn>,
    data_out: Option<DataOut>,
    send_packet: Option<SendPacket>,
    is_busy: Option<unsafe extern "C" fn(*mut c_void) -> bool>,
    data_ready: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, *mut u8, u16) -> i32>,
    setting: Option<unsafe extern "C" fn(u32, *mut u8, u16, *mut c_void)>,
    interface_descriptor_size: u8,
    interface_descriptor: *const u8,
    interface_association_descriptor_size: u8,
    interface_association_descriptor: *const u8,
    bos_descriptor_size: u8,
    bos_descriptor: *const u8,
    cookie: *mut c_void,
}

// SAFETY: the table is immutable and only read by the single-threaded USB stack.
unsafe impl Sync for ClassInfo {}

static END_POINT: EndPointInfo = EndPointInfo {
    ep_in_addr: EP_IN,
    ep_in_size: REPORT_SIZE as u16,
    ep_out_addr: EP_OUT,
    ep_out_size: REPORT_SIZE as u16,
    ep_type: EP_TYPE_INTERRUPT,
};

static DESCRIPTOR_BYTES: [u8; 32] = DESCRIPTORS;
static REPORT_DESCRIPTOR_BYTES: [u8; 34] = REPORT_DESCRIPTOR;

/// The class the stack's `USBD_LEDGER_start` registers for the FIDO interface. Not reachable from
/// Rust code, hence `#[used]`; the C stack references it by name.
#[used]
#[unsafe(export_name = "USBD_LEDGER_HID_U2F_class_info")]
static CLASS: ClassInfo = ClassInfo {
    class_type: CLASS_HID_U2F,
    end_point: &END_POINT,
    init: Some(init),
    de_init: Some(de_init),
    setup: Some(setup),
    ep0_rx_ready: None,
    data_in: Some(data_in),
    data_out: Some(data_out),
    send_packet: Some(send_packet),
    // Never busy for the stack: a FIDO response in flight must not hold up replies on the Ledger
    // APDU interface, which the stack waits on through this callback.
    is_busy: None,
    // Requests never go to the application through the stack's buffer: the transport hands them
    // out itself.
    data_ready: None,
    // The stack's U2F settings (versions, capabilities, first channel) are for the C transport;
    // the core transport has its own.
    setting: None,
    interface_descriptor_size: DESCRIPTORS.len() as u8,
    interface_descriptor: DESCRIPTOR_BYTES.as_ptr(),
    interface_association_descriptor_size: 0,
    interface_association_descriptor: core::ptr::null(),
    bos_descriptor_size: 0,
    bos_descriptor: core::ptr::null(),
    cookie: core::ptr::null_mut(),
};

unsafe extern "C" {
    fn USBD_LL_PrepareReceive(
        pdev: *mut c_void,
        ep_addr: u8,
        pbuf: *mut u8,
        size: u32,
    ) -> UsbdStatus;
    fn USBD_LL_Transmit(
        pdev: *mut c_void,
        ep_addr: u8,
        pbuf: *const u8,
        size: u32,
        timeout_ms: u32,
    ) -> UsbdStatus;
    fn USBD_CtlSendData(pdev: *mut c_void, pbuf: *mut u8, len: u32) -> UsbdStatus;
}

/// Largest CTAP response the application builds; getInfo, the only command so far, needs a few
/// dozen bytes.
const RESPONSE_SIZE: usize = 1024;

/// What INIT reports: the application version, CBOR only (U2F messages are not implemented).
const DEVICE_INFO: DeviceInfo = DeviceInfo {
    version: [
        version_part(env!("CARGO_PKG_VERSION_MAJOR")),
        version_part(env!("CARGO_PKG_VERSION_MINOR")),
        version_part(env!("CARGO_PKG_VERSION_PATCH")),
    ],
    cbor: true,
    msg: false,
};

/// A version number of at most 255, as INIT carries one byte per part.
const fn version_part(text: &str) -> u8 {
    let bytes = text.as_bytes();
    let mut value: u32 = 0;
    let mut at = 0;
    while at < bytes.len() {
        let digit = bytes[at];
        assert!(digit.is_ascii_digit(), "a version part is decimal");
        value = value * 10 + (digit - b'0') as u32;
        assert!(value <= 255, "a version part fits one byte");
        at += 1;
    }
    value as u8
}

/// The request buffer, also reported as `maxMsgSize`: the largest message the framing allows,
/// so a PING of any length round-trips.
const MESSAGE_SIZE: u16 = MAX_MESSAGE_SIZE as u16;

/// The device settings getInfo reports.
const SETTINGS: Settings = Settings {
    max_msg_size: match MaxMsgSize::new(MESSAGE_SIZE) {
        Ok(size) => size,
        Err(_) => panic!("the framing maximum is above the 1024-byte minimum"),
    },
};

/// Everything the class keeps between callbacks.
struct Hid {
    transport: Transport<MAX_MESSAGE_SIZE, &'static mut [u8; MAX_MESSAGE_SIZE]>,
    authenticator: Authenticator,
    response: &'static mut [u8; RESPONSE_SIZE],
    /// The stack's device handle, from the last callback that carried it; null before the
    /// interface is configured.
    pdev: *mut c_void,
    /// A report is in the IN endpoint and the host has not read it yet.
    in_flight: bool,
    /// A report taken from the transport that the stack did not accept; sent before anything
    /// else, so a response is never left with a hole.
    pending: Option<Report>,
    /// The OUT endpoint is left unarmed because the transport cannot take a report yet
    /// ([`Transport::can_receive`]); armed again once it can.
    out_paused: bool,
    /// Transport clock: [`TICK_MS`] per ticker event.
    now_ms: u64,
}

/// A zero-initialized static buffer, handed out once as `&'static mut`. The device's linker
/// script refuses initialized data in RAM, so everything large starts as zero bytes.
struct Buffer<const N: usize>(UnsafeCell<[u8; N]>);

// SAFETY: `start` hands each buffer out once, on the only thread.
unsafe impl<const N: usize> Sync for Buffer<N> {}

static MESSAGE: Buffer<MAX_MESSAGE_SIZE> = Buffer(UnsafeCell::new([0; MAX_MESSAGE_SIZE]));
static RESPONSE: Buffer<RESPONSE_SIZE> = Buffer(UnsafeCell::new([0; RESPONSE_SIZE]));

/// The class state, uninitialized until [`start`]. The application is single-threaded and the
/// stack calls the class only from `os_io_rx_evt`, which nothing here calls while holding the
/// state, so a borrow conflict is a programming error that `RefCell` turns into a panic instead
/// of aliasing.
struct Global {
    started: Cell<bool>,
    hid: UnsafeCell<MaybeUninit<RefCell<Hid>>>,
}

// SAFETY: there is one thread and no interrupt handler runs Rust code.
unsafe impl Sync for Global {}

static HID: Global = Global {
    started: Cell::new(false),
    hid: UnsafeCell::new(MaybeUninit::uninit()),
};

/// Sets up the class state; called once, first thing in the application, before any event can
/// reach the class.
pub fn start() {
    assert!(!HID.started.get(), "the FIDO HID class starts once");
    // SAFETY: the guard above makes this the only time the buffers are borrowed.
    let (message, response) = unsafe { (&mut *MESSAGE.0.get(), &mut *RESPONSE.0.get()) };
    let hid = Hid {
        transport: Transport::new(DEVICE_INFO, message),
        authenticator: Authenticator::new(SETTINGS),
        response,
        pdev: core::ptr::null_mut(),
        in_flight: false,
        pending: None,
        out_paused: false,
        now_ms: 0,
    };
    // SAFETY: not started yet, so nothing refers to the slot.
    unsafe { (*HID.hid.get()).write(RefCell::new(hid)) };
    HID.started.set(true);
}

/// Runs `f` on the class state; `None` before [`start`].
fn with_hid<R>(f: impl FnOnce(&mut Hid) -> R) -> Option<R> {
    if !HID.started.get() {
        return None;
    }
    // SAFETY: `start` initialized the slot and nothing ever takes it apart.
    let cell = unsafe { (*HID.hid.get()).assume_init_ref() };
    let mut hid = cell
        .try_borrow_mut()
        .expect("the USB class is never re-entered");
    Some(f(&mut hid))
}

impl Hid {
    /// Answers a request the transport handed out and sends what is due.
    fn handle(&mut self, event: Event) {
        match event {
            Event::Request { .. } => {
                if let Some(request) = self.transport.request() {
                    let length = self.authenticator.process(request, &mut self.response[..]);
                    self.transport
                        .respond(&self.response[..length], self.now_ms)
                        .expect("the response buffer is smaller than the transport's and the request is still active: nothing ran in between");
                }
            }
            // Requests are answered as soon as they arrive, so there is no wait to cancel yet.
            Event::Cancel { .. } | Event::None => {}
        }
        self.pump();
    }

    /// Puts the next report into the IN endpoint if it is free, then arms the OUT endpoint again
    /// if it was held back and the transport can take a report now.
    fn pump(&mut self) {
        if !self.in_flight && !self.pdev.is_null() {
            let report = match self.pending.take() {
                Some(report) => Some(report),
                None => self.transport.next_report(self.now_ms),
            };
            if let Some(report) = report {
                // SAFETY: `pdev` is the handle the stack passed to the class; the stack copies
                // the report out before returning.
                let status = unsafe {
                    USBD_LL_Transmit(self.pdev, EP_IN, report.as_ptr(), REPORT_SIZE as u32, 0)
                };
                if status == USBD_OK {
                    self.in_flight = true;
                } else {
                    // Retried on the next completion or tick.
                    self.pending = Some(report);
                }
            }
        }
        if self.out_paused && !self.pdev.is_null() && self.transport.can_receive() {
            // SAFETY: `pdev` is the stack's handle; a null buffer lets the stack deliver the
            // report in its own transfer buffer.
            let status = unsafe {
                USBD_LL_PrepareReceive(self.pdev, EP_OUT, core::ptr::null_mut(), REPORT_SIZE as u32)
            };
            // Retried on the next completion or tick when the stack refuses.
            self.out_paused = status != USBD_OK;
        }
    }

    /// Forgets the transaction and every queued report, wiping the buffer.
    fn reset(&mut self) {
        self.transport.restart();
        self.in_flight = false;
        self.pending = None;
        self.out_paused = false;
    }
}

/// Advances the transport clock by one ticker interval: times out stalled messages, schedules
/// keepalives and sends what is due. Called by the main loop on every ticker event.
pub fn tick() {
    with_hid(|hid| {
        hid.now_ms = hid
            .now_ms
            .checked_add(TICK_MS)
            .expect("a u64 millisecond clock outlives the device");
        hid.transport.poll(hid.now_ms);
        hid.pump();
    });
}

/// Class `init`: the interface was configured; the transport starts over for the host.
unsafe extern "C" fn init(pdev: *mut c_void, _cookie: *mut c_void) -> UsbdStatus {
    with_hid(|hid| {
        hid.reset();
        hid.pdev = pdev;
    });
    // SAFETY: `pdev` is the stack's handle; a null buffer lets the stack deliver the report in
    // its own transfer buffer.
    unsafe { USBD_LL_PrepareReceive(pdev, EP_OUT, core::ptr::null_mut(), REPORT_SIZE as u32) }
}

/// Class `de_init`: the interface is gone; nothing more can be sent, and whatever a request in
/// progress left in the buffer is wiped now rather than at the next configuration.
unsafe extern "C" fn de_init(_pdev: *mut c_void, _cookie: *mut c_void) -> UsbdStatus {
    with_hid(|hid| {
        hid.reset();
        hid.pdev = core::ptr::null_mut();
    });
    USBD_OK
}

/// Class `setup`: the standard and HID class requests addressed to the interface.
unsafe extern "C" fn setup(
    pdev: *mut c_void,
    _cookie: *mut c_void,
    request: *mut SetupRequest,
) -> UsbdStatus {
    // SAFETY: the stack passes the setup packet it is processing.
    let Some(request) = (unsafe { request.as_ref() }) else {
        return USBD_FAIL;
    };
    // bmRequestType (USB 2.0 §9.3): bit 7 direction (1 device-to-host), bits 6..5 type (0
    // standard, 1 class), bits 4..0 recipient (1 interface). Every request is matched with its
    // direction, so one with a data stage the other way is refused rather than answered.
    const STANDARD_IN: u8 = 0x81;
    const STANDARD_OUT: u8 = 0x01;
    const CLASS_IN: u8 = 0xA1;
    const CLASS_OUT: u8 = 0x21;
    // Answers sent from statics: the stack may still read them after this call returns.
    static ZERO_STATUS: [u8; 2] = [0, 0];
    static ZERO: [u8; 1] = [0];
    let send = |data: &'static [u8]| {
        let length = data.len().min(usize::from(request.w_length));
        // SAFETY: `pdev` is the stack's handle and `data` lives for the whole program; the stack
        // only reads it.
        unsafe { USBD_CtlSendData(pdev, data.as_ptr().cast_mut(), length as u32) }
    };
    match (request.bm_request, request.b_request) {
        // GET_STATUS: no remote wakeup, not halted (USB 2.0 §9.4.5).
        (STANDARD_IN, 0x00) => send(&ZERO_STATUS),
        // CLEAR_FEATURE: nothing to clear on the interface.
        (STANDARD_OUT, 0x01) => USBD_OK,
        // GET_DESCRIPTOR of the HID or report descriptor (HID 1.11 §7.1.1).
        (STANDARD_IN, 0x06) => match (request.w_value >> 8) as u8 {
            HID_DESCRIPTOR_TYPE => {
                send(&DESCRIPTOR_BYTES[HID_DESCRIPTOR_AT..HID_DESCRIPTOR_AT + HID_DESCRIPTOR_LEN])
            }
            REPORT_DESCRIPTOR_TYPE => send(&REPORT_DESCRIPTOR_BYTES),
            _ => USBD_FAIL,
        },
        // GET_INTERFACE: the only alternate setting is 0; SET_INTERFACE accepts only that one.
        (STANDARD_IN, 0x0A) => send(&ZERO),
        (STANDARD_OUT, 0x0B) if request.w_value == 0 => USBD_OK,
        // HID class requests (HID 1.11 §7.2): no idle rate and no boot protocol to keep, so
        // GET_IDLE and GET_PROTOCOL report zero and the SET requests are accepted as no-ops.
        (CLASS_IN, 0x02 | 0x03) => send(&ZERO),
        (CLASS_OUT, 0x0A | 0x0B) => USBD_OK,
        _ => USBD_FAIL,
    }
}

/// Class `data_in`: the host read the report in the IN endpoint; the next one can go.
unsafe extern "C" fn data_in(pdev: *mut c_void, _cookie: *mut c_void, _ep: u8) -> UsbdStatus {
    with_hid(|hid| {
        hid.pdev = pdev;
        hid.in_flight = false;
        hid.pump();
    });
    USBD_OK
}

/// Class `data_out`: a report arrived on the OUT endpoint.
unsafe extern "C" fn data_out(
    pdev: *mut c_void,
    _cookie: *mut c_void,
    _ep: u8,
    packet: *mut u8,
    length: u16,
) -> UsbdStatus {
    // Every report on this interface is 64 bytes (§11.2.4, the report descriptor above); a
    // shorter or empty transfer is not a report and is dropped rather than padded into one.
    let report: Option<Report> = if packet.is_null() || usize::from(length) != REPORT_SIZE {
        None
    } else {
        // SAFETY: the stack passes its transfer buffer holding `length` received bytes.
        let received = unsafe { core::slice::from_raw_parts(packet, REPORT_SIZE) };
        received.try_into().ok()
    };
    let arm = with_hid(|hid| {
        hid.pdev = pdev;
        if let Some(report) = &report {
            let event = hid.transport.receive(report, hid.now_ms);
            hid.handle(event);
        }
        // A full error queue holds the host back: the endpoint stays unarmed until the queued
        // errors have been sent (`pump`).
        let arm = hid.transport.can_receive();
        hid.out_paused = !arm;
        arm
    })
    .unwrap_or(true);
    if !arm {
        return USBD_OK;
    }
    // SAFETY: `pdev` is the stack's handle; the endpoint is armed for the next report.
    unsafe { USBD_LL_PrepareReceive(pdev, EP_OUT, core::ptr::null_mut(), REPORT_SIZE as u32) }
}

/// Class `send_packet`: the stack's path for messages built outside the class. Everything on
/// this interface is built by the transport, so nothing legitimately comes this way.
unsafe extern "C" fn send_packet(
    _pdev: *mut c_void,
    _cookie: *mut c_void,
    _packet_type: u8,
    _packet: *const u8,
    _length: u16,
    _timeout_ms: u32,
) -> UsbdStatus {
    USBD_FAIL
}
