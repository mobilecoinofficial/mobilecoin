# mc-transaction-std

Transaction utilities that are client-oriented, may change relatively often,
and don't get linked into the enclaves. They may require `std` (but currently don't).

This crate currently provides the transaction-builder object, and functionality
related to memos.
