//! The user interface the device provides: a ceremony that waits for the user. The command logic
//! asks, the platform shows its screen and answers; while it waits it keeps the transport going
//! (keepalives, CANCEL) and gives up after the timeout it was given.

/// How long a ceremony waits for the user (CTAP 2.2 §6.9 and every command asking for user
/// presence): after this, the request ends with CTAP2_ERR_USER_ACTION_TIMEOUT.
pub const USER_ACTION_TIMEOUT_MS: u32 = 30_000;

/// What the user is asked to confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prompt {
    /// authenticatorSelection (§6.9): the platform asks which of the connected authenticators
    /// the user means.
    Selection,
}

/// How a confirmation ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The user confirmed: user presence.
    Confirmed,
    /// The user explicitly refused.
    Rejected,
    /// The platform cancelled the request (CTAPHID_CANCEL, or its channel was reset).
    Cancelled,
    /// Nobody answered within the timeout.
    TimedOut,
}

/// How a built-in user verification ended: the user re-entered the device PIN in the ceremony
/// and the operating system checked it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    /// The operating system validated the PIN.
    Verified,
    /// The PIN was wrong; built-in verification is blocked until a correct entry restores the
    /// operating system's count.
    Invalid,
    /// Not offered: the operating system's count is not full, so one more wrong entry would bring
    /// the device closer to its wipe. The platform falls back to the client PIN.
    Blocked,
    /// The user backed out of the keypad.
    Rejected,
    /// The platform cancelled the request.
    Cancelled,
    /// Nobody answered within the timeout.
    TimedOut,
}

/// The device's screens. Calls block until the user answers, the platform cancels, or the
/// timeout passes.
pub trait Ui {
    /// Asks the user to confirm `prompt` within `timeout_ms`.
    fn confirm(&mut self, prompt: Prompt, timeout_ms: u32) -> Answer;

    /// Asks the user to enter the device PIN within `timeout_ms` and has the operating system
    /// check it. Offered only while the operating system's retry count is full, so the
    /// application spends at most one of the device's tries before a correct entry.
    fn verify_user(&mut self, timeout_ms: u32) -> Verification;
}
