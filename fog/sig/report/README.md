This crate creates and verifies signatures over Fog reports returned by the report server.

It does this by providing two traits, a [`Signer`](crate::Signer) and [`Verifier`](crate::Verifier), along implementations for the [`Ed25519Public`](mc_crypto_keys::Ed25519Public) and [`Ed25519Pair`](mc_crypto_keys::Ed25519Pair) types.

The signature itself is implemented by first taking an [`&[Report]`](mc_fog_api::Report) slice, and constructing a [`Digestible`](mc_crypto_digestible::Digestible) semantic hash of the structure, then using the [`schnorrkel`](schnorrkel) crate to produce a signature over the resulting hash. This crate simply ensures any implementation details of the signature production and verification (e.g. the schnorrkel context tag) are kept and tested together.

This crate is designed to work inside an enclave, and therefore is no-std, and has no direct FFI dependencies.
