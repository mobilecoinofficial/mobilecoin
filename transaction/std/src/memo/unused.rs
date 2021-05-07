//! Object for Unused memo type

use mc_transaction_core::MemoPayload;

/// A memo that the sender declined to use to convey any information.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct UnusedMemo;

impl From<UnusedMemo> for MemoPayload {
    fn from(_: UnusedMemo) -> MemoPayload {
        MemoPayload::default()
    }
}
