//! CTAP2 dispatch and authenticatorGetInfo against CTAP 2.2 §6.4 and §8. Expected responses are
//! written out byte by byte, never produced by the code under test.

use super::{
    AAGUID, Authenticator, CommandCode, MaxMsgSize, Settings, StatusCode, TooSmall, UnknownCommand,
};
use crate::cbor::{self, validate};

fn settings() -> Settings {
    Settings {
        max_msg_size: MaxMsgSize::try_from(1024).expect("at least 1024"),
    }
}

fn process(request: &[u8]) -> Vec<u8> {
    let mut authenticator = Authenticator::new(settings());
    let mut response = [0u8; 256];
    let length = authenticator.process(request, &mut response);
    response[..length].to_vec()
}

/// getInfo answers CTAP2_OK and the map {1: [], 3: AAGUID, 5: 1024} in canonical order: the
/// required versions and aaguid, and the transport's maxMsgSize (§6.4).
#[test]
fn get_info_reports_the_implemented_members() {
    let response = process(&[0x04]);
    let mut expected = vec![0x00, 0xA3, 0x01, 0x80, 0x03, 0x50];
    expected.extend_from_slice(&AAGUID);
    expected.extend_from_slice(&[0x05, 0x19, 0x04, 0x00]);
    assert_eq!(response, expected);
    assert_eq!(validate(&response[1..]), Ok(()), "canonical CBOR");
}

/// The AAGUID is the fixed UUID 8f920f83-9da2-4861-94d7-7f3c9945d532 in network order.
#[test]
fn aaguid_is_the_application_uuid() {
    assert_eq!(
        AAGUID,
        [
            0x8f, 0x92, 0x0f, 0x83, 0x9d, 0xa2, 0x48, 0x61, 0x94, 0xd7, 0x7f, 0x3c, 0x99, 0x45,
            0xd5, 0x32
        ]
    );
}

/// getInfo has no parameters; bytes after the command are an invalid length.
#[test]
fn get_info_with_parameters_is_invalid_length() {
    assert_eq!(process(&[0x04, 0xA0]), [StatusCode::InvalidLength as u8]);
}

/// An empty request has no command byte: CTAP1_ERR_INVALID_LENGTH.
#[test]
fn an_empty_request_is_invalid_length() {
    assert_eq!(process(&[]), [0x03]);
}

/// §8.1: a command the authenticator does not implement, defined or not, is
/// CTAP1_ERR_INVALID_COMMAND with no body.
#[test]
fn unimplemented_commands_are_invalid_command() {
    for code in [
        0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x40, 0x41, 0xFF,
    ] {
        assert_eq!(process(&[code, 0xA0]), [0x01], "command {code:#04x}");
    }
}

/// A response that does not fit is CTAP1_ERR_OTHER, and an empty buffer gets nothing.
#[test]
fn a_response_that_does_not_fit_is_other() {
    let mut authenticator = Authenticator::new(settings());
    let mut small = [0u8; 8];
    assert_eq!(authenticator.process(&[0x04], &mut small), 1);
    assert_eq!(small[0], 0x7F);
    assert_eq!(authenticator.process(&[0x04], &mut []), 0);
}

/// §8: an authenticator accepts messages of at least 1024 bytes, so no smaller maxMsgSize can
/// be reported.
#[test]
fn max_msg_size_is_at_least_1024() {
    assert_eq!(MaxMsgSize::try_from(1023), Err(TooSmall(1023)));
    assert_eq!(MaxMsgSize::try_from(0), Err(TooSmall(0)));
    assert_eq!(MaxMsgSize::try_from(1024).map(MaxMsgSize::get), Ok(1024));
    assert_eq!(MaxMsgSize::try_from(7609).map(MaxMsgSize::get), Ok(7609));
}

/// Command codes are the ones of §6; unknown codes come back as the error value.
#[test]
fn command_codes_follow_the_specification() {
    let table = [
        (0x01, CommandCode::MakeCredential),
        (0x02, CommandCode::GetAssertion),
        (0x04, CommandCode::GetInfo),
        (0x06, CommandCode::ClientPin),
        (0x07, CommandCode::Reset),
        (0x08, CommandCode::GetNextAssertion),
        (0x09, CommandCode::BioEnrollment),
        (0x0A, CommandCode::CredentialManagement),
        (0x0B, CommandCode::Selection),
        (0x0C, CommandCode::LargeBlobs),
        (0x0D, CommandCode::Config),
    ];
    for (code, command) in table {
        assert_eq!(CommandCode::try_from(code), Ok(command));
        assert_eq!(command as u8, code);
    }
    assert_eq!(CommandCode::try_from(0x03), Err(UnknownCommand(0x03)));
}

/// §8: canonical-form violations are CTAP2_ERR_INVALID_CBOR (0x12), wrong member types
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE (0x11).
#[test]
fn cbor_errors_map_to_their_status_codes() {
    assert_eq!(StatusCode::from(cbor::Error::Malformed) as u8, 0x12);
    assert_eq!(StatusCode::from(cbor::Error::NotCanonical) as u8, 0x12);
    assert_eq!(StatusCode::from(cbor::Error::TooDeep) as u8, 0x12);
    assert_eq!(StatusCode::from(cbor::Error::UnexpectedType) as u8, 0x11);
}

/// Status codes carry the values of the §8.2 table.
#[test]
fn status_codes_follow_the_specification() {
    let table = [
        (StatusCode::Ok, 0x00),
        (StatusCode::InvalidCommand, 0x01),
        (StatusCode::InvalidParameter, 0x02),
        (StatusCode::InvalidLength, 0x03),
        (StatusCode::InvalidSeq, 0x04),
        (StatusCode::Timeout, 0x05),
        (StatusCode::ChannelBusy, 0x06),
        (StatusCode::LockRequired, 0x0A),
        (StatusCode::InvalidChannel, 0x0B),
        (StatusCode::CborUnexpectedType, 0x11),
        (StatusCode::InvalidCbor, 0x12),
        (StatusCode::MissingParameter, 0x14),
        (StatusCode::LimitExceeded, 0x15),
        (StatusCode::FpDatabaseFull, 0x17),
        (StatusCode::LargeBlobStorageFull, 0x18),
        (StatusCode::CredentialExcluded, 0x19),
        (StatusCode::Processing, 0x21),
        (StatusCode::InvalidCredential, 0x22),
        (StatusCode::UserActionPending, 0x23),
        (StatusCode::OperationPending, 0x24),
        (StatusCode::NoOperations, 0x25),
        (StatusCode::UnsupportedAlgorithm, 0x26),
        (StatusCode::OperationDenied, 0x27),
        (StatusCode::KeyStoreFull, 0x28),
        (StatusCode::UnsupportedOption, 0x2B),
        (StatusCode::InvalidOption, 0x2C),
        (StatusCode::KeepaliveCancel, 0x2D),
        (StatusCode::NoCredentials, 0x2E),
        (StatusCode::UserActionTimeout, 0x2F),
        (StatusCode::NotAllowed, 0x30),
        (StatusCode::PinInvalid, 0x31),
        (StatusCode::PinBlocked, 0x32),
        (StatusCode::PinAuthInvalid, 0x33),
        (StatusCode::PinAuthBlocked, 0x34),
        (StatusCode::PinNotSet, 0x35),
        (StatusCode::PuatRequired, 0x36),
        (StatusCode::PinPolicyViolation, 0x37),
        (StatusCode::RequestTooLarge, 0x39),
        (StatusCode::ActionTimeout, 0x3A),
        (StatusCode::UpRequired, 0x3B),
        (StatusCode::UvBlocked, 0x3C),
        (StatusCode::IntegrityFailure, 0x3D),
        (StatusCode::InvalidSubcommand, 0x3E),
        (StatusCode::UvInvalid, 0x3F),
        (StatusCode::UnauthorizedPermission, 0x40),
        (StatusCode::Other, 0x7F),
    ];
    for (status, value) in table {
        assert_eq!(status as u8, value, "{status:?}");
    }
}
