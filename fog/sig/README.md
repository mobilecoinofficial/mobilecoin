This code (and the associated crates bundled here) provide support for the *Fog Signature Scheme*.

## This Crate

This crate provides a `Verifier` trait and an implementation for [`PublicAddress`](mc_account_keys::PublicAddress). This trait contains a single method, `verify_fog_sig()`, which is used to verify a user has signed off on a list of Attestation Verfiication Reports for ingest enclaves.

## In Context

Fog works by having a sender encrypt a transaction's destination public address using a cryptobox-like scheme based on Ristretto255 and AES-256-GCM. The sender looks up a destination user's fog server, determines the appropriate ingest enclave's Ristretto public key, and encrypts the recipient's public address for that enclave.

This family of crates provides primatives to authenticate that a particular user has delegated fog operations (via a chain of trust) to a list of particular ingest server public keys.

## Related Crates

There are three distinct crates which come together to implement the Fog Signature Scheme:

| Crate | Purpose |
| ----- | ------- |
| `mc-fog-sig-authority` | Signatures over DER-encoded `subjectPublicKeyInfo` bytes |
| `mc-fog-sig-report` | Signatures over [`Report[]`](mc_fog_api::Report) structures |
| `mc-fog-sig` | One-shot validation of [`ReportRequest`](mc_fog_api::ReportRequest) using a [`PublicAddress`](mc_account_keys::PublicAddress)

## Scheme Details

What we want to do is provide a way for the recipient to that they trust a particular fog operator (so far as they need to), and for that fog operator to provide a list of ingest Attestation Verification Reports (from Intel's IAS service), and for a sender to be able to verify this.

### Recipients

Recipient applications perform the following steps for their users:

1. Using the private cryptonote view key (a Ristretto255 scalar), creates a digital signature over a long-lived X.509 certificate authority controlled by the Fog operator.
1. Publishes a [`PublicAddress`](mc_account_keys::PublicAddress), which contains containing the "Fog URL" (where to query the operator for reports), the "Fog Signature" (raw [`Signature`](schnorrkel::Signature) bytes), and a report ID.

### Fog Operators

The fog operator, for its part, performs the following steps:

1. Provides the recipient an X509 root certificate (or it's `subjectPublicKeyInfo` bytes) for use in the recipient's step 1 (outside the scope of this crate).
1. Uses the root certificate to sign zero or more intermediate authorities (outside the scope of this crate).
1. Uses the last authority to sign an Ed25519 leaf key/certificate pair for use by a Fog report server (outside the scope of this crate).
1. Operates a fog report server which reads a list of [`VerificationReport`](mc_attest_core::VerificationReport) structures provided by ingest servers under the operator's control, and signs a [`ReportResponse`](mc_fog_api::ReportResponse) object upon request.

### Senders

Sending applications, in turn:

1. Examine a recipient's [`PublicAddress`](mc_account_keys::PublicAddress) for fog support (outside the scope of this crate).
1. Contact the user's indicated fog report server, and request the report response object, which contains a signature and chain and list of report objects (outside the scope of this crate).
1. Verify the certificate chain is correct (signatures are right), valid (for the current time), and terminates in a self-signed root certificate and no certificates are expired.
1. Verify the recipient's view key was used to sign the root certificate.
1. Verify the leaf key of the chain was used to sign the list of [Report](mc_fog_api::Report) structures.

After verifying the authenticity of the fog operator's list of reports, senders should also verify the report objects themselves contain valid Attestation Verification Report structures, which are signed by IAS and contain expected MRSIGNER or MRENCLAVE values, debug settings, etc., but this happens outside the scope of the `mc-fog-sig`* family of crates.
