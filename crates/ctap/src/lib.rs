//! FIDO2 / CTAP authenticator logic for Ledger devices.
//!
//! The crate is `no_std` with `alloc` so the device application links it as is; the `std`
//! feature (on by default) is for host users such as tests and tools.
//!
//! - [`ctaphid`]: the USB HID transport (framing, reassembly, channels).
//! - [`cbor`]: the CTAP2 canonical CBOR encoding.
//! - [`ctap2`]: CTAP2 command dispatch, status codes and authenticatorGetInfo.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod cbor;
pub mod ctap2;
pub mod ctaphid;
