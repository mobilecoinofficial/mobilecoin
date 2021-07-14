//! MobileCoin SLIP-0010-Based Key Derivation

#![no_std]
#![warn(missing_docs)]
#![deny(unsafe_code)]
#![feature(external_doc)]
#![doc(include = "../README.md")]

extern crate alloc;

use alloc::borrow::ToOwned;
use bip39::{Mnemonic, Seed};
use core::result::Result as CoreResult;
use curve25519_dalek::scalar::Scalar;
use displaydoc::Display;
use hkdf::Hkdf;
use mc_account_keys::{AccountKey, Error as AccountKeyError};
use mc_crypto_keys::RistrettoPrivate;
use sha2::Sha512;
use zeroize::Zeroize;

/// An enumeration of errors which can occur while working with SLIP-0010 key
/// derivation
#[derive(Debug, Display, Eq, PartialEq)]
pub enum Error {
    /// There was an error creating the account key: {0}
    AccountKey(AccountKeyError),
}

/// The result type
pub type Result<T> = CoreResult<T, Error>;

/// A key derived using SLIP-0010 key derivation
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Slip10Key([u8; 32]);

impl AsRef<[u8]> for Slip10Key {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Create the view and spend private keys, and return them in reverse order,
/// e.g. `(spend, view)`, to match
/// [`AccountKey::new()`](mc_account_key::AccountKey::new)
impl From<Slip10Key> for (RistrettoPrivate, RistrettoPrivate) {
    fn from(src: Slip10Key) -> (RistrettoPrivate, RistrettoPrivate) {
        let mut okm = [0u8; 64];

        let view_kdf = Hkdf::<Sha512>::new(Some(b"mobilecoin-ristretto255-view"), src.as_ref());
        view_kdf
            .expand(b"", &mut okm)
            .expect("Invalid okm length when creating private view key");
        let view_scalar = Scalar::from_bytes_mod_order_wide(&okm);
        let view_private_key = RistrettoPrivate::from(view_scalar);

        let spend_kdf = Hkdf::<Sha512>::new(Some(b"mobilecoin-ristretto255-spend"), src.as_ref());
        spend_kdf
            .expand(b"", &mut okm)
            .expect("Invalid okm length when creating private spend key");
        let spend_scalar = Scalar::from_bytes_mod_order_wide(&okm);
        let spend_private_key = RistrettoPrivate::from(spend_scalar);

        (spend_private_key, view_private_key)
    }
}

impl From<[u8; 32]> for Slip10Key {
    fn from(src: [u8; 32]) -> Self {
        Self(src)
    }
}

/// A default derivation of the [`Slip10Key`] from a
/// [`Mnemonic`](tiny_bip39::Mnemonic).
///
/// This is equivalent to calling `mnemonic.derive_slip10_key(0)`.
impl From<Mnemonic> for Slip10Key {
    fn from(src: Mnemonic) -> Slip10Key {
        src.derive_slip10_key(0)
    }
}

/// A common interface for constructing a [`Slip10Key`] for MobileCoin given an
/// account index.
pub trait Slip10KeyGenerator {
    /// Derive a MobileCoin SLIP10 key for the given account from the current
    /// object
    fn derive_slip10_key(self, account_index: u32) -> Slip10Key;
}

/// The BIP44 "usage" component of a BIP32 path.
///
/// See https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki for more details.
const USAGE_BIP44: u32 = 44;
/// The MobileCoin "coin type" component of a BIP32 path.
///
/// See https://github.com/satoshilabs/slips/blob/master/slip-0044.md for reference.
const COINTYPE_MOBILECOIN: u32 = 866;

// This lets us get to
// Mnemonic::from_phrases().derive_slip10_key(account_index).
// try_into_account_key(...)
impl Slip10KeyGenerator for Mnemonic {
    fn derive_slip10_key(self, account_index: u32) -> Slip10Key {
        // We explicitly do not support passphrases for BIP-39 mnemonics, please
        // see the MobileCoin Key Derivation design specification, v1.0.0, for
        // design rationale.
        let seed = Seed::new(&self, "");

        // This is constructing an `m/44/866/<idx>` BIP32 path for use by SLIP-0010.
        let path = [USAGE_BIP44, COINTYPE_MOBILECOIN, account_index];

        // We're taking what the SLIP-0010 spec calls the "Ed25519 private key"
        // here as our `Slip10Key`. That said, we're not actually using this as
        // an Ed25519 key, just IKM for a pair of HKDF-SHA512 instances whose
        // output will be correctly transformed into the Ristretto255 keypair we
        // need.
        //
        // This will also transform any "unhardened" path components into their
        // "hardened" version.
        let key = slip10_ed25519::derive_ed25519_private_key(seed.as_bytes(), &path);

        Slip10Key(key)
    }
}

impl Slip10Key {
    /// Try to construct a new [`AccountKey`](mc_account_keys::AccountKey) from
    /// an existing [`Slip10Key`].
    // In the future, AccountKey::new_with_fog will be fallible.
    pub fn try_into_account_key(
        self,
        fog_report_url: &str,
        fog_report_id: &str,
        fog_authority_spki: &[u8],
    ) -> Result<AccountKey> {
        let (spend_private_key, view_private_key) = self.into();
        Ok(AccountKey::new_with_fog(
            &spend_private_key,
            &view_private_key,
            fog_report_url,
            fog_report_id.to_owned(),
            fog_authority_spki,
        ))
    }
}

impl From<Slip10Key> for AccountKey {
    fn from(src: Slip10Key) -> AccountKey {
        let (spend_private_key, view_private_key) = src.into();
        AccountKey::new(&spend_private_key, &view_private_key)
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use bip39::Language;

    /// Test vector built using SLIP10 outputs and ristretto vectors
    struct SlipToRistretto {
        slip10_hex: &'static str,
        view_hex: &'static str,
        spend_hex: &'static str,
    }

    /// An array of slip-to-ristretto test vectors, generated using the
    /// slip2ristrettovec.py script.
    const SLIPKEY_TO_RISTRETTO_TESTS: [SlipToRistretto; 12] = [
        // Seed1, chain m
        SlipToRistretto {
            slip10_hex: "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
            view_hex: "5a8d2f490f1e76ca0b7d14f37ce2b1a797b8e5e5c88b636e0c9b4b27b83c017a87cbd4a31a6f09ff0a896575f7a950743035cbe887c0e739d0104ed351397950",
            spend_hex: "34359a3c11ee05fa89fee68c66310448be52e4aacd21df68b1ea0e192786f2743c79edd445b14e411e96fdd6916721a31da4e0eb20011df9861269ac8ca76651",
        },
        // Seed1, chain m/0h
        SlipToRistretto {
            slip10_hex: "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
            view_hex: "ed78027e8bbfed790bfd82c8a7b09d4ebdeae64a34c9bccd8ba8b5f53e8175cb1f39a25a6e7af66ce164221d66ddcaabcfc3b46e9d2016c6853a58104bcb966e",
            spend_hex: "e9977192e47181c745ef2ec6aea0891317e286eff2b79839038ed69fc8a9607801b63d400f3f8225758b0033bef0044006e9aa1d801af3cde2d10bd885b23219",
        },
        // Seed1, chain m/0h/1h
        SlipToRistretto {
            slip10_hex: "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
            view_hex: "8da3648d1287e149ecaef02262c10b553e9db725513a16b4e551b5905b1c584835609d6f5de35a599042b4aca518be8d245dfd23ab85d888d9b8878d390dd0d3",
            spend_hex: "e5e34e1df7a634bcd5c5dabe4165f8fe4563e6eca60d140d64a60553d91b5612f7b5433e0e9b2a0b5db8890565480ec2b0cc36c83abc53b9d830bdd8ba89b339",
        },
        // Seed1, chain m/0h/1h/2h
        SlipToRistretto {
            slip10_hex: "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
            view_hex: "704e6f3367f791a92a2f51b7464a9c0939069588184f889db79fa41296579bc45467108987d53c2db9721ab9e8b83c8fb8a221b8ed0d2f25ed499c8ffa463cf4",
            spend_hex: "3da2b9a45da40a74ef575cc1f797f1af9d8aaa0c56e3aa5d4c4fe9d9fefc7ed8ab6605a527425c333877e3d860a38916f37cec3e3eca30e596fa72bf13ec72de",
        },
        // Seed1, chain m/0h/1h/2h/2h
        SlipToRistretto {
            slip10_hex: "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
            view_hex: "17c55ed9d315d3354d9002585e9e36d8d4a59c2d81dbf6f79f34cde17c037bb5a75369a06013eea62b7d031cf6d29e4aa2076f9616515eadc80f13c4d5e8d335",
            spend_hex: "b4e77a241249fb329edc03b5e23ad55c4ac59c624937e13f53e9f8cb1d48b519e60b01c40f7a390cf2ccc5ddfc50aa9eabaa5fe45467fc306c84e643740d2eaa",
        },
        // Seed1, chain m/0h/1h/2h/2h/1000000000h
        SlipToRistretto {
            slip10_hex: "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
            view_hex: "cc1625738ea9cd53c5249e5d7a8d48137954bd0635a4c9de8d66e05ea85b26685dfc02d96d2b801870b43df2f9ab4d5a8d99795ebc2612bbdbd1f47ee93ad437",
            spend_hex: "e66dbc9006aa58d33ab44f09cc8430617836e5be3445d5ef4e4a72d7a9e08aa8562464cbdcbf5fd04c5cd0a606b9ab263742ef0833a6a383ada36464512543dc",
        },

        // Seed 2, chain m
        SlipToRistretto {
            slip10_hex: "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
            view_hex: "252b64e72ce233d4f0722271a87800b30066e02d88888f5f02e118c17fd5fec6d575f629655fcb290fe0c0af3753cc11059d2905b60e966f1149dfcfebc41911",
            spend_hex: "60b498483f453f941e9de4f2f5f77aef14662fd03091f9dad337a2e7dd0935b56200a943749b31400f13c750c694114d8b0824e036db456bb90d41a96355c845",
        },
        // Seed 2, chain m/0h
        SlipToRistretto {
            slip10_hex: "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
            view_hex: "e38c79fde4d2765d12194877c609ca71f4b9dec9fe3257f73d984be88dae3b40645b89a122ce6c58f91d00ac4e1c2dab8f270946cc622e18557a0c8c32c8324e",
            spend_hex: "46cecebccce9dd56f668f73d401304acc1a99a790fb6fe4e42e007e0affcef5367284f8e2ae3cef534ef9d8494ffaa9aba077f1b907e38c33e8a904bbe0db646",
        },
        // Seed 2, chain m/0h/2147483647h
        SlipToRistretto {
            slip10_hex: "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
            view_hex: "338b5d54caa54d6603a965eaefa5496b3f080e91d040eedee68861845dacf36aa9e0290e2132657d146e2c99993e0f6ff07427571856e56bb1f789bfda73ca9c",
            spend_hex: "3d50ae00c8c57754251c6e56da7a3225319d17b522d26cd68db65819b2241fe8d0745269f2452c65a87cfb0c01e01e99524932635f0f901d22b9a90d0417c736",
        },
        // Seed 2, chain m/0h/2147483647h/1h
        SlipToRistretto {
            slip10_hex: "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
            view_hex: "692cf43116bf4d7c916b20ddafc9994af1ec0f44cd1442b7a97f1f132b0851561a890d9fb7fd3fc4a7bc518d7cd59fb376f5c26f1bddbc06cfbd55f706a86dce",
            spend_hex: "caef63e15caee473afc52cc7dbdec61a04bb076a40a51d7acc534266a79c83c881219a1dd1961a3afa9ad4490a0da1759e7cc29a490d706dd5892119c5d14636",
        },
        // Seed 2, chain m/0h/2147483647h/1h/2147483646h
        SlipToRistretto {
            slip10_hex: "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
            view_hex: "f304957a698bb5bb8bdba551fb41d09989da619c220a471f14481e0c6517d5802bb243abe85b356e0f9787f130cf32a47f0742527e205c42434dad1ab8c0f173",
            spend_hex: "8df044dfcdc8a4bce6cac272def5de78538200c6d6fac148a4c3cdf45a6be60c368e3f187d32155e1b75fd936e1ef97af6f5604cd876075c4171ea0f56c8a3cd",
        },
        // Seed 2, chain m/0h/2147483647h/1h/2147483646h/2h
        SlipToRistretto {
            slip10_hex: "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
            view_hex: "54236b7a6c8edc075f36faf4a8fa253cede026c655dc8b32bd87edb8cb18a76e30639f4f384cd2986e813ac74ce213199315847fef246092dbdab06c8163f104",
            spend_hex: "68a4ac670f7431ebdfde157ee4ab2a9a84e539f438acd364bc0543bf4deb3d106cbea42e0682de712e018b92503344b80e698a701e3bcba4ffceeb0f4afd3086",
        },
    ];

    #[test]
    fn slip10key_into_account_key() {
        for data in SLIPKEY_TO_RISTRETTO_TESTS.iter() {
            // Maybe make Slip10Key implement hex::FromHex?
            let mut key_bytes = [0u8; 32];
            hex::decode_to_slice(data.slip10_hex, &mut key_bytes[..])
                .expect("Could not decode SLIP10 test vector output");

            let slip10_key = Slip10Key::from(key_bytes);

            let mut expected_view_bytes = [0u8; 64];
            hex::decode_to_slice(data.view_hex, &mut expected_view_bytes)
                .expect("Could not decode view-key bytes");
            let expected_view_scalar = Scalar::from_bytes_mod_order_wide(&expected_view_bytes);
            let expected_view_key = RistrettoPrivate::from(expected_view_scalar);

            let mut expected_spend_bytes = [0u8; 64];
            hex::decode_to_slice(data.spend_hex, &mut expected_spend_bytes)
                .expect("Could not decode spend-key bytes");
            let expected_spend_scalar = Scalar::from_bytes_mod_order_wide(&expected_spend_bytes);
            let expected_spend_key = RistrettoPrivate::from(expected_spend_scalar);

            let account_key = AccountKey::from(slip10_key);

            assert_ne!(
                AsRef::<[u8]>::as_ref(&expected_view_key),
                AsRef::<[u8]>::as_ref(&expected_spend_key)
            );
            assert_eq!(
                AsRef::<[u8]>::as_ref(&expected_view_key),
                AsRef::<[u8]>::as_ref(account_key.view_private_key())
            );
            assert_eq!(
                AsRef::<[u8]>::as_ref(&expected_spend_key),
                AsRef::<[u8]>::as_ref(account_key.spend_private_key())
            );
        }
    }

    /// A test vector using
    struct MnemonicToRistretto {
        phrase: &'static str,
        account_index: u32,
        view_hex: &'static str,
        spend_hex: &'static str,
    }

    /// These are the strings used in the [BIP39 test vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json).
    ///
    /// In those tests it's assumed the password is "TREZOR", but it's safe to
    /// assume these wordlists are all burned. This particular structure was
    /// generated using this command:
    ///
    /// ```bash
    /// ./mnemonic2slip.py \
    ///     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
    ///     "legal winner thank year wave sausage worth useful legal winner thank yellow" \
    ///     "letter advice cage absurd amount doctor acoustic avoid letter advice cage above" \
    ///     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong" \
    ///     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent" \
    ///     "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will" \
    ///     "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always" \
    ///     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when" \
    ///     "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" \
    ///     "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title" \
    ///     "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless" \
    ///     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote" \
    ///     "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic" \
    ///     "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog" \
    ///     "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length" \
    ///     "scheme spot photo card baby mountain device kick cradle pact join borrow" \
    ///     "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave" \
    ///     "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside" \
    ///     "cat swing flag economy stadium alone churn speed unique patch report train" \
    ///     "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access" \
    ///     "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform" \
    ///     "vessel ladder alter error federal sibling chat ability sun glass valve picture" \
    ///     "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump" \
    ///     "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"
    /// ```
    const EN_MNEMONIC_STRINGS: [MnemonicToRistretto; 48] = [// Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            account_index: 0,
            view_hex: "e60abdbb6b46bcb34c24c232e4461ee3de964b3f460cccd9fa2ac75ae2b28a19f71389015d1c67a7dc8d84e15eaf8245d2c413b6f6b5069c5d93f49baa410f62",
            spend_hex: "290383347788fd93c878a3f35cdfab30033276ef34a6df99cc8bf6a963ed74128e34f6c6e1022813236c6b22ef851d5403fbbed7c06b5df547e5e1e64c4bb022",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            account_index: 1,
            view_hex: "fc463f5e0339f64a33e4e1109b823e3c455778d6aaeb22350099901ec09f4be54f5f064a55ab70ed530ddb1bc6109748ef32f86d350c4f3a2b24dc789417e2a5",
            spend_hex: "f357477b6ee7917ac3fc0415969ae8654f2eda17d604064970b6ac13dba860306f964c41388f8271af50729e227d0dbf0420551a4958ce40efcb146db2f3fbe0",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "legal winner thank year wave sausage worth useful legal winner thank yellow",
            account_index: 0,
            view_hex: "f91c5068f6bd8f63c3c2c30621ed87621ddede8f131a76432cee816dbd84a7d2f83669366c5e51e83779168a856c5cc926164bea24bc0fa69d43c16b7bdc9dea",
            spend_hex: "18b66268ad126db62a45d6bf782811c29af1e44ff4402da87eea04e2b33c51aa4907f66a39c9039bdd58d89f26b987afd7f7aad7ae6b46bc1c6bd6cf0f22227d",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "legal winner thank year wave sausage worth useful legal winner thank yellow",
            account_index: 1,
            view_hex: "c7d52b4f744a31dd1ec4408c08aa13bb179018494ff0c636db40ca0a60172cfa0ef3788ee35255acd59013460cbab263ff4d48aed80f960dc6b661da150098b2",
            spend_hex: "b02777704984bb7b340e1e11b354742aef65e44c057b4142de145d17befb8b7467ed2e2ac28746d2188fa2b111f68ecf30d89cd682e803884b997eb01b6d0acb",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            account_index: 0,
            view_hex: "202e4561ad8ffb0267581d26d922b4d2701fa78a5c22042c51f18a376a22c0c3365921c3a61c995b541cdf36ed2ced36b21a4a8ce9ce133cf8c0d82449dff004",
            spend_hex: "2c13c547ba47c674400aca8218bd1c41605df9aa3747c70b5eb98118b255bfbbd67cde8d8ff6a153c0c9ed927e9a849331481781a500512b4cf7fe731e2d3706",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            account_index: 1,
            view_hex: "eb0e103760ae6cc266c0e8480ad36607dfa41713ce03ed224316dfc7e9678c19df28edc0f566eb59623b79c51f971a0460ba36938b1be0582bf0a9f5a53e6759",
            spend_hex: "a0ff94aa07f55fc55206c42a2f392cb0799b6651581506810e7ddf910f60200b285542a30ea8d7199dcaf6d1ad13c6d1912ce669735f116b30332a0507a7b105",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            account_index: 0,
            view_hex: "ade167a8ea0d1ed54ea4fcb8ffd98123e606adf34d2796f3a4f759939c11132053478d2055ef62260c9f4557c3962a1cf7c1e42a442effcee40d5f61133b32a9",
            spend_hex: "212ccaef63bb3a7591991b75e30f5c5017ee4c1cd7c2e3d1e90bb3a32485d7dcd1d10c7321604a68620a160872230b29e07b5ac9bb1c6ca5cc902fb5e3836fac",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            account_index: 1,
            view_hex: "ff27df80555896e8a967c47dab77e9a05756602cfd933e0ba3f350558de9f734f9ae713dd87eee704fc55ba074577cb192b59ded38c14fcc435f9bf51d025370",
            spend_hex: "a5cd5d3d0504646b2a8a82a28708522987230088ffb733f10c7b39ff08a65def8ee37705f3e54671d4b481f9129e391537f000d0753a2504bc3ccbb6a38ebe0e",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            account_index: 0,
            view_hex: "70c48e2377c2ed6d358ec0aebaa340852d23f15e8a75781b0c1210dd8705df1d52a2823833b59ad3af058756fc9d185864085878b083f2ea742336ad9714ac2a",
            spend_hex: "0729302d6037105e8ca7464336511caa7d4c73e60e0d82046bb35606a36835764a62332a5c7f0c857067ca521d20e01486cf14cc694f261d3f849408da43f516",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            account_index: 1,
            view_hex: "a4d8e53b4ed6fea1d990c8767fb01231dd223b92d35bad30c098f3fda698e6b2d7f7b81b0eb59ce9160bfbb0ec666876ce86df75f552d1d58a34a23971e00698",
            spend_hex: "05372c5bebbc09a219a35d7af39a348faf7bea10a3cdea850d291fda7166d02e1dc207827fd90151b83b278f959992f58b550029963c6c0584bd9dbae0d74e48",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            account_index: 0,
            view_hex: "da3ae36fbc4d251d2d2e095c0d94c537ccc7b330486b8ef05c14c0149c40c5e4789643680d05034e14abfca8ba44e4a81be7a3143b6320a7845940e9cfe9b979",
            spend_hex: "cd185d503a84ea857404c2fa4ad74816d764029e758fd5f08b3e2dfb51467baef29c8ccd3aa2055d19e1bd4701bdafc802ab41f99e3d06b905b789b6061f4013",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            account_index: 1,
            view_hex: "53a68f40fecec62dca274b12e17a311e39d58a943bb0ca85db92fe509acb7e605f0d6d45dc38e6e9247a0dbf316cf5c3d88ba6426f7ce3ad03c3562400972bee",
            spend_hex: "954f7a3833b730bc7bb819a3a6fd6079cd7a6e6a05a41b7f4bfc7ebcf416e3ce6184b3af00b5babb748563d87da7b8db219de001bef2a74bdd0952a09ad5b616",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            account_index: 0,
            view_hex: "c7514e29687e73b26f4ac95aa1cff820c06583c942a949dcf8c7f89c37dc6311b82e73e5002ce4b48f5f025f49dc87fe5d091a7b1038b234526d159f883c422b",
            spend_hex: "e1e46ad482ebfe38b8dfad21c71bfae4d9ee261c7e9aedd044686424176a16f0e9ad418a8cc59461ee31e9f850b778e06961fce04076a75c3e5aae091377cab7",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            account_index: 1,
            view_hex: "a41d701487a470ed1f9d182d7fcd67d9d98e659d59e55bc07074498a91cdc384821b647b735102c7dbb6cafdd7012505e2215d72cc3a599165fbeeaf9056df65",
            spend_hex: "402a264656fdc0c8fa830ca588b003f24cc42437ed1800ea1ccde100363bbbb2f9cc2b5f1a14455edc356eaf0f221ed0acf9fab26a99dba12758fa7ba8729540",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            account_index: 0,
            view_hex: "412340d6b94f6b3e3823386d2ce037885ee1430dd286aaa94107389165f4f13c0077e0100b4bf09bf3fcb81f97e22609950a1aa3107ebb891d79dad1ccf9eea5",
            spend_hex: "9e5cec675ad02ebede6ed891cf824024dcb61718415d4e761fff571d786313447155bd084b09cc7b88c7b70c43ab5d1990515f15c98e61e6d1d792c50a555ef3",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            account_index: 1,
            view_hex: "d58ffa7697831c5dd44c40865ee6f00d12cb731f57c2d4b2b8dfc4ce8d5a1916b9ee083b9d36d3124e67d71cdb88f2724e525e1d244732c35faba9ac1c1d596f",
            spend_hex: "153f195291dbbf0a82bbd35544a0647ea88150a802c31f2dde723b5926422a522f50f140f28e1e0ec5c92ef624ac394c8ec913c1617cde6542616b357bf9800f",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            account_index: 0,
            view_hex: "4ab6041974d9f32a49d8f8e9c96c958c80cdb2261b1d964d588704f32d1bc7e4f139fb0f20d33e4a329b2e0de63a5e09a7b333a32b8df69ec7a0946b001f2785",
            spend_hex: "ada65765f7f8d13e9e6600e9cb49d5fbec586f7455f16c7741621b8bb9c411101ae9f83be2077b9f7f7ff6eb344ffb99837b84acf688b723f24951727fe14a25",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            account_index: 1,
            view_hex: "1ec6e3ce98fead794d5c2f5852ff1404e920d0fbb9cf3a457861e7127642fc5644cc38b8c6d2f1e5bc35cf65be3a97d2306b309d7c84b5400419b77c1a97b804",
            spend_hex: "3044415f0235e7e9704dd439e47ceba8c3323fff2eb3273bffa776d1c7651dae4aa0a3de2c9e3b70005aff745df48abeea6a6df8dd94f87ee1d0cccd775850bc",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            account_index: 0,
            view_hex: "92366562217464fefac36a914acb483a48cd50d9ac0fde6067d5bd7e3f796d516c9c7a87a7d0f7807369e2fadc3f7ea4c0bed93161d1113e3b763a66fad8a643",
            spend_hex: "86f44eeae04c323c7977d5d32399b7dc4b51596651d00508eec822242b041ccb42a75f122db2a3a9bec8aeb707079b89f4098bbab798e7e4e98baa5966f94169",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            account_index: 1,
            view_hex: "9026d71c7742870ef51c5525ea94f08791ff175e7d4b4bdcfb5e8176e27b543f420b17ba5d02a2a2fff16d1449589ab4f35323695899dce932e538302985a207",
            spend_hex: "3e183b105843a0a7709333600c1d6233ff64d24ced366ec3ffe49d22d8b8e7aa9895819e784df50e3037b754ab2f3df112caee85cd22c1796cc94937eb35c4ea",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            account_index: 0,
            view_hex: "534dcd3768040f8e8c22ab06291a4a6e1054f7963e40171a6848b9eea4e78e89d09af928c26e3fcfa154fcf0916c7ba6159b0a5e304e19bc78387a6f34eabac4",
            spend_hex: "40f96d1fb392a04c2ed59531d12c12e0fdc8f0ae2f30cdc5e7cb1e269769dd8a24f6c785bc77c11e69329e50e847f6a3426e12048f23ba15b59cd09d8e191386",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            account_index: 1,
            view_hex: "b4416bbba159dc1bc1c7aa689faed2bf3c24116badd4e0e0d5231c77167e158b708bec6d71458e105c161702a6d3d51c7ea5a799b09bab838c86879efcf76af1",
            spend_hex: "a31c371c61385e09814d4291dda24901c355b3992ae84382df2c8e4f2ff82c38ae6f963d77120ac032085e9b6ffd0d3895ae78d97d282099759493c64b246087",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            account_index: 0,
            view_hex: "41b4efb4a40a87f9cdbdc3b58334a0e973b87f3a74b2f06a523696d1ce7e046bff96c8faf34aa1aa11c27f74d0d87d885fd1bab8187baaa1b63b9ef89c106ebb",
            spend_hex: "c0461cae6d6ee6095ae9388fe2516c5cd6b5a8571551f9b49f83dc23bd8b2c7289ac72367cb014a9e7c297a860ee54b5c1b79b24c1c29da9848b35d50e613ea3",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            account_index: 1,
            view_hex: "5bddef43fbbfdd094069a35b8906c01ae0269291f72745d2c9b8ed1ebb719313e7f753681ea623e259a2e2986f5c6123a07b3bb944b09721c6b14e27095aa976",
            spend_hex: "7918a94df5ee675f9d7a91c1bda23348f4ca9dac8bc7f0cdbacac40d42db90db14ef454c80c8f41a6adc70ff3fd2cb5457c4988547b3cbd13dca09a97a9eb2a5",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            account_index: 0,
            view_hex: "58dcf1bbe93b2691d79a449e2c6e08cadffb3c0a28ad58d964b97bc6525dd739c04feb4d685ec5c1af923528bf3b122d4f0df99174632037fd7a9876d95ecb14",
            spend_hex: "0a4960b57be1d6e0c4c431595862364f4a5d9f33d32525175d76fe60c74e6b261c67073bcf43ac7d4890c1b2a5d54f42439e84322f1372acf58909205d3198e5",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            account_index: 1,
            view_hex: "889387d17970851eee2263ff69323ad59991d304629afa0c34afb2ce88c7303780d497a5d66252e090101235ad894495bd53d7694e2091da7886f95b6f7e769d",
            spend_hex: "a86fefee3a0023fe62ff3552a3ce67663387efa4aa99518b2ea3a5ce5c51b3be7024fcbd4565870ae6f79fca627a53c96a91edfe43e48608002fc0cc8b9d35f0",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
            account_index: 0,
            view_hex: "1cd3dd23f5ce851a1d83e4471be473edf76557d138f5ba5f6079ff71ede01c7069cd958b61a1305e38eb14975c80ae82ccb4c5eccd7f18a1c81a3f8b2a939c39",
            spend_hex: "65bc69ef2e84e663648b5940d2b49e7d65d0fee989b3ba09c285eb64abd45b56c7eeee08146764ae82ec9e56a8b3647cec05e754deecc0e6af5ee67ada90b7f4",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
            account_index: 1,
            view_hex: "fd29bb5845d1254bfb96cda30318972a0b3e1e3b420cdd284f406a06ecce5210474a595de883a52b71e6b2bdfea00de51b297a381cdffe83461ab5d0214706fb",
            spend_hex: "e77379827aaf40ff76e13e40b4f1b40fd261fdbf3a42ac606d915e9989aab37d497d54fa96a4ec5e1a7f5c53721e84b9528027ca72d7156cd9855897891851b8",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            account_index: 0,
            view_hex: "2a25f8379e510a9f98dd8c83ba1b20dcd6a1ec8b7fd11ac42a115c4c2bfcac6f0d8b09fc6a6ebaae27ea69ab5a3d1da7df6f0c313c82307538240be235493e89",
            spend_hex: "9d231d98f64b8e51aa1f75c980096f32940c0cf69a53868f9bf552b509b73b919745c686d60ac11b64bbe73eec9e024a468422c3f712519407314d763b52843d",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            account_index: 1,
            view_hex: "340400ea3c47ee8286afdb8cb5a39010f27ed614e4ab3ce91e3f2f363818c95f3e8f4e9d97274f847c8d50505520ea822d365bb5c569f62e8cc44151d75592d5",
            spend_hex: "d879552e9570202ebda58990a75f18270849c89dd8ec40e73983ed64d6428fd4369f71e44714ed5acb31d17f08a7fc8fd81be300eebe05ba5913d187b8e23552",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "scheme spot photo card baby mountain device kick cradle pact join borrow",
            account_index: 0,
            view_hex: "c1a2b43c716fccc639b1a6246e905762cbee358b436387cc613a79c45849c28facdf6e4aaf9b7f50e4e9bf7f4e58bff98dccc663f28e4a28f60b915837407db2",
            spend_hex: "70ea0fd06293564a76a58de7cd6039b3fc924204d5878f2fe6814c237ac7fbbc419eb70dc7837c968854509fb6234ccf9116cd7ffb27bdd9df32ba01c9fe02b0",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "scheme spot photo card baby mountain device kick cradle pact join borrow",
            account_index: 1,
            view_hex: "bc6c24c30b9060e01950fac1a5d5c491090f643dfe8be2a6ec301e1cb08458a18f0ed331722b445621b5666dca5c1359563d67b9cd289aa27ff7b09ec12fcb48",
            spend_hex: "2950c8ced3e50c171bfa40317f38a52d15a908b9713b08fa36175947c433d9ae0aa4108e7a8199572fa0810056dd4cd05c9586c4defe0afaca598cb35d2d5f57",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
            account_index: 0,
            view_hex: "e667b4b7029e9c9c06786d8fa2b709d6a48fd4cff738355716ff469a243fdc40764c07cd764be259e006fb22097c8c65a7d3e1b71bdf51f266b8945ece7b6ea6",
            spend_hex: "ec531d4bde1c7cad6eb904dde7b15bbc94642cbbb551f928296ff3a388e04a24cb55b13d5c17e1716994a6338bb46ec4b0ef2acbfe76b3b3cf23ccbe17d5bdbc",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
            account_index: 1,
            view_hex: "05c65be4f1e735eba32ecab9833cd395acb35a3b1e64fe4569f25bd56fd53048a3e308d3417116aad264fc1d51c0c45518753ecaf0fdf5f0f07bef6c2eaa18c3",
            spend_hex: "8eddba4a8d0eb6dc8af5b57f96900b94a1afcb88821c8e25b6528d52944ab47bce2b4cb0caeb7d44d4c8ea19bb5c737e601c04225cad31ac6199bf6622d89c9b",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            account_index: 0,
            view_hex: "be265d3f1ecce2830e682a4d2ed754f98487fcb32b8e3461f344092f0bb089303f5c5b2a939face114f5b261a04ae345d684bca0ef114a94dd83383d7828c707",
            spend_hex: "75d2518ef07fd34bde19166ebf9af89bba20bf39761bc16fabf5837177ea5d7a7ebf4f40c77af3d4dd9042d80bb94a60d243cdaff88e7236d4feb57582c4ff4d",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            account_index: 1,
            view_hex: "94905bfb581ee3a050724ef1c413cbe65512a86be38352977cf0f5d65c19b15ea1d13688ff76bf27915bd4b2cf9379cae2af10ab9dbe20be78640c01fbd9a9da",
            spend_hex: "5342cc3d661314319e7220a9d34fddf61cb4ff9ba80f5dd68aeace28caad704eb4e4815dd375d4195966acf00115ab52b0a4fb67b1b81e79ad82b343a07f65a1",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "cat swing flag economy stadium alone churn speed unique patch report train",
            account_index: 0,
            view_hex: "42f9e9eeab40301854c14440920bcd7c5f8dbee70fa0c7eebf102e3a5e367ff975621dc0363bf9e55c7645936d5c7146a907d96286bc70662042d567ccbe386a",
            spend_hex: "4af25d4f760ddec7fbfbe0b7852666aa0a1b87abbc361e64ebdfae26cc9d82c3ce4bc396db87786337e02299d47a0b2c305b4c2dcb44e11ab87609119e54ef1d",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "cat swing flag economy stadium alone churn speed unique patch report train",
            account_index: 1,
            view_hex: "56c1318fdb93b434475f12737e8b94a0502d774f751b5e02ad5afa88e8f25bb4fb6b415eedf9927333be6c01f96fe9a6623bd1d44a358f80d8508ea7aa54dc4e",
            spend_hex: "484794591314b9ccdcea4aac7655b8f98418de82830642e76d972b3695849e72183978274e29de7773cd03e6957730f45601a7a1e9d7eefee604d78f40822278",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
            account_index: 0,
            view_hex: "23eb58dd532e80cef0772b0415b9b3b8d3da4c0427c295865f839febb0ce5ed8aca584afc2d097983eb49e08897d78c37878d5d4e00f069ffa2331571db2b956",
            spend_hex: "1e1ff479932b2723eec5b24e5f8a58b43a599867778dacf933117cdc87947b72f93e5a3eab6cb3d70a080ed497e1abf9af452ef4784ea71f298cdc5e64dce314",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
            account_index: 1,
            view_hex: "4e190e25dd12f0c6ba3319f1ad7fa868622b4ba5cf7785dc98cc09a7ca5dfafc5f3d27f5b56b2dbf688354cf6aa8b4a615e2e953ace6278d14dc59ee27caefc0",
            spend_hex: "ac0d884be61c54b76e9c49d9c068141bd3a1b003f509b274b91ca8c4fc80a7c49d1825964adcf4d1976c6031a972b2b02deb4880022befb4789f39540cfb7270",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            account_index: 0,
            view_hex: "3471ad1cae238b02e8fee729d04fd45c8ca8c91c141c75dbe89c47e78dcccd430aed8f78cceeedd7c7ba548b8ae32501951679f025a15bf6ddcc14cafd2836db",
            spend_hex: "37ec88f0bc514d13e2c795f57a980461990d11a66a1255fd3b432d1d5367982ea7d1396ea7a53c96cb200d473dc196cddd1065c5814f2cb6d6ad4cefc252092e",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            account_index: 1,
            view_hex: "40aa28ae6022141535dbf2703619fb6a56dc7994218e143287ca6343401effa33e969c2c24e13c34c0de978249ae191b8caefed5f3258967c68c023ad584fb73",
            spend_hex: "71a02f9e9217a5928ff6b46202648f4f18575bbb27e08560b83e483060da80ccdf56bf19edec4cdc4915157f2cd5f9c2712bd69ba23202ca3dff025bb54a4144",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "vessel ladder alter error federal sibling chat ability sun glass valve picture",
            account_index: 0,
            view_hex: "38cc9bb5994553120ef065eabe9d094b7bcef00fc4fcbead4c7b8d01f18b92cad0b0027e5277a751e46c89452272debbd8f818f7011a7be493e3c4bfac5da71a",
            spend_hex: "fc935be921e75c85bc7e168a0ab861b19529cd24a56e9c5d10d677ffcee55eae383f1a1bf7ae4d82d97b2036ba848e470a6b1f9f8fc72deab0bc169f8e2c893f",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "vessel ladder alter error federal sibling chat ability sun glass valve picture",
            account_index: 1,
            view_hex: "53ff60800bd8479ef5fc1f3699404029423a99ccc5e6c4c45513d51a6a2b59a168becb43fad6c5223e700893e441d734005e0c24850234217b06b87aea6301f8",
            spend_hex: "d960234ec22cad5d8e355f16e7e5fa09d1676189a0246c2ad815e8c7be59416bf222b2f96f4e9912236c9894c9aa6d9704fbef0be0cb3eec0155150de06b6ad1",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
            account_index: 0,
            view_hex: "f09e2c5efcf7e5482e6afa4d0bd80a2dfc3fb2650c1da030f764b6118fbba2dc4b8b98cf0c6abb72f02afe669231e7839e175b9ebfd3dc6e97fba9ee5a46d9ba",
            spend_hex: "c80947469d4d694779f49a010633628100804454fcc78f0aaa7e4fac1253ab6dc93816153805ddc9ea8c74538e71a7d25534e17b374b244a96cb38610d1b48e9",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
            account_index: 1,
            view_hex: "df344386e61e46c13b3aab3b3044c172c878aaaa050d57fe7969b6ecee4a34d4c84b7782f0da1860053e8bf9ec1f198865470d70836b376d7708172b924268b5",
            spend_hex: "a0e74e73f90a6dda13dd5aed01a16ef1cf3356eb06f88362bf0dab55dac08fc094cc92e916b8148b1c4c2ed4d91ee2cb4eb9dd9154775939c70e375c6acc9baa",
        },
        // Path: m/44'/866'/0'
        MnemonicToRistretto {
            phrase: "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            account_index: 0,
            view_hex: "a93f976cdce8c2a975c7bb50fa05095c28a8ba735a555e08051a5c38fb835a4e664593a9f2a8a77a72b985fbcb68570d299fa36888899336a5f08125edc53295",
            spend_hex: "cfe38b011230806ff090e938b669535df087d8475cd280f089d7e554593e08ecff710c13a73aba3659255c9d08a33cc24fed9947b7af2a212bce2454faf6be02",
        },
        // Path: m/44'/866'/1'
        MnemonicToRistretto {
            phrase: "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            account_index: 1,
            view_hex: "a2715afec916ee62d4b117397f7c1868877f56cd6bce82cc28e8278ebfb1bf3eacc79953629e06961370401c66d0335ef881d5dc43f393f8d0835811e3de5108",
            spend_hex: "2285d224077b99af07e49a85083cc65109f2401697784e6f959da668b248b34f174673a54fbe91bfe6ef5f2e38d8674962d91134637f04a69897d93b0c5dff24",
        },
    ];

    #[test]
    fn mnemonic_into_account_key() {
        for data in EN_MNEMONIC_STRINGS.iter() {
            std::eprintln!(
                "Generating for phrase {} at path m/44'/866'/{}'",
                data.phrase,
                data.account_index
            );
            let mnemonic = Mnemonic::from_phrase(data.phrase, Language::English)
                .expect("Could not read test phrase into mnemonic");
            let key = mnemonic.derive_slip10_key(data.account_index);
            let account_key = AccountKey::from(key);

            let mut expected_view_bytes = [0u8; 64];
            hex::decode_to_slice(data.view_hex, &mut expected_view_bytes)
                .expect("Could not decode view-key bytes");
            let expected_view_scalar = Scalar::from_bytes_mod_order_wide(&expected_view_bytes);
            let expected_view_key = RistrettoPrivate::from(expected_view_scalar);

            let mut expected_spend_bytes = [0u8; 64];
            hex::decode_to_slice(data.spend_hex, &mut expected_spend_bytes)
                .expect("Could not decode spend-key bytes");
            let expected_spend_scalar = Scalar::from_bytes_mod_order_wide(&expected_spend_bytes);
            let expected_spend_key = RistrettoPrivate::from(expected_spend_scalar);

            assert_ne!(
                AsRef::<[u8]>::as_ref(&expected_view_key),
                AsRef::<[u8]>::as_ref(&expected_spend_key)
            );
            assert_eq!(
                AsRef::<[u8]>::as_ref(&expected_view_key),
                AsRef::<[u8]>::as_ref(account_key.view_private_key())
            );
            assert_eq!(
                AsRef::<[u8]>::as_ref(&expected_spend_key),
                AsRef::<[u8]>::as_ref(account_key.spend_private_key())
            );
        }
    }
}
