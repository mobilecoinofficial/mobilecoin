# MobileCoin Key Derivation

This crate implements a standard method for deriving a MobileCoin [`AccountKey`](mc_account_keys::AccountKey) from entropy using the following procedure:

1. A cryptographically secure random number generator is used to gather 32 bytes of entropy.
1. These bytes are mapped into a BIP-39-compliant [`Mnemonic`](tiny_bip39::Mnemonic) seed phrase.
1. The ([NFKD normalized](https://en.wikipedia.org/wiki/Unicode_equivalence#Normal_forms)) UTF-8 seed phrase is hashed using an empty-string password according to [the BIP-39 specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed) into a [`Seed`](tiny_bip39::Seed).
1. Using the [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) compliant [BIP-32 path](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) `m/44'/866'/<account>'`, the seed bytes are hashed again, according to the [SLIP-0010 procedure for Ed25519 curves](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) to deterministically generate the resulting child key.
1. The resuting [`Slip10Key`](crate::Slip10Key) is expanded into the necessary Ristretto255 scalars used as CryptoNote view and spend keys using HKDF-SHA512, salted with the byte strings `b"mobilecoin-ristretto255-view"` and `b"mobilecoin-ristretto255-spend"`, respectively.

## Usage

The usage is fairly straightforward, you start with a mnemonic, convert to a [`Slip10Key`](crate::SLip10Key), and then on to an [`AccountKey`](mc_account_key::AccountKey).

```
use mc_account_keys::AccountKey;
use mc_account_keys_slip10::Slip10KeyGenerator;
use bip39::{Language, Mnemonic};

// Create a new mnemonic from random bytes
let mnemo = Mnemonic::new(Language::English);

// FIXME: Let the user backup their phrase

// Create a SLIP-0010 private child key for account "1"
let slip10 = mnemo.derive_slip10_key(1)

// Derive the AccountKey from the Slip10Key
let account_key = AccountKey::from(slip10);

// go forth and spend money!
```

To restore an account from a backup phrase, you would use [`Mnemonic::from_phrase()`](tiny_bip39::Mnemonic::from_phrase()) instead of `::new()`.

## In Context

This is intended to be the primary method for creating new account keys for MobileCoin. It superceeds the simpler `RootEntropy`-based scheme, which unfortunately does not have a proof of security.

Within the larger cryptocurrency ecosystem, there are multiple relevant standards used in this crate:

 * [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) defines a scheme to generate a "seed phrase" taken by mapping random bytes into a (pre-agreed) word list, and hashing that "phrase" into into seed entropy.
 * [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) defines a scheme to derive hierarchical child keys for the bitcoin curve from a given numeric path. The path through the hierarchy is what concerns us in this crate.
 * [BIP-0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) define a scheme for using BIP-32 paths to derive keys for multiple coins from a single "seed entropy".
 * [SLIP-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) is a reference of coin type values for use with BIP-44, of which MobileCoin is `866`.
 * [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) describes generation of keypairs for elliptic curves other than the one used by Bitcoin. We deviate slightly from it's *intent*, in that we do not use what it terms the "ed25519 private key" directly, but rather merely as the last round of hash input to generate the necessary Ristretto255 scalar values (used for the CryptoNote View/Spend private keys).
