//! Defines an object for each known high-level memo type,
//! and an enum to allow matching recovered memos to one of these types.
//!
//! To add a new memo type, add a new module for it, add a structure,
//! and make it convertible to MemoPayload.
//! Then also add it to the MemoType enum and extend the TryFrom logic.

use core::convert::TryFrom;
use displaydoc::Display;
use mc_transaction_core::MemoPayload;

mod authenticated_sender;
mod destination;
mod unused;

pub use authenticated_sender::{AuthenticatedSenderMemo, SenderMemoCredential};
pub use destination::{DestinationMemo, DestinationMemoError};
pub use unused::UnusedMemo;

/// An enum over memo types known at this revision
#[derive(Clone, Debug)]
pub enum MemoType {
    /// An unused memo -- the sender didn't want to write anything
    Unused(UnusedMemo),
    /// A memo that identifies the sender to the recipient in an authenticated
    /// way
    AuthenticatedSender(AuthenticatedSenderMemo),
    /// A memo that can record the destination of funds in a transaction
    Destination(DestinationMemo),
}

/// An error that can occur when trying to interpret a raw MemoPayload as
/// a MemoType
#[derive(Clone, Display, Debug)]
pub enum MemoDecodingError {
    /// Unknown memo type: type bytes were {0:02X?}
    UnknownMemoType([u8; 2]),
}

impl TryFrom<&MemoPayload> for MemoType {
    type Error = MemoDecodingError;
    fn try_from(src: &MemoPayload) -> Result<Self, Self::Error> {
        let memo_type: [u8; 2] = *src.get_memo_type();
        // The first byte is conceptually a "type category"
        // The second byte is a type within the category
        match memo_type[0] {
            0u8 => match memo_type[1] {
                0u8 => Ok(MemoType::Unused(UnusedMemo {})),
                1u8 => Ok(MemoType::AuthenticatedSender(
                    AuthenticatedSenderMemo::from(src.get_memo_data()),
                )),
                _ => Err(MemoDecodingError::UnknownMemoType(memo_type)),
            },
            16u8 => match memo_type[1] {
                1u8 => Ok(MemoType::Destination(DestinationMemo::from(
                    src.get_memo_data(),
                ))),
                _ => Err(MemoDecodingError::UnknownMemoType(memo_type)),
            },
            _ => Err(MemoDecodingError::UnknownMemoType(memo_type)),
        }
    }
}
