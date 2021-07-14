This crate creates and verifies signatures over the `subjectPublicKeyInfo` bytes of a fog operator's root certificate authority.

It performs this work by providing a pair of traits: `Signer` and `Verifier`, and providing implementations of them for the [`RistrettoPrivate`](mc_crypto_keys::RistrettoPrivate) and [`RistrettoPublic`](mc_crypto_keys::RistrettoPublic) types, respectively. The signature itself is implemented by [`schnorrkel`](schnorrkel) crate to produce a signature over the given bytes, this simply ensures any implementation details of the signature production and verification happen together.

This crate is designed to work inside an enclave, and therefore is no-std, and has no direct FFI dependencies.
