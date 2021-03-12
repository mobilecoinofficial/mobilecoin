use mc_account_keys::{AccountKey, RootIdentity};
use mc_test_vectors_definitions::account_keys::*;
use mc_util_test_vector::write_jsonl;
use std::convert::TryFrom;

fn main() {
    write_jsonl("../vectors", || {
        (0..10)
            .map(|n| {
                let root_entropy = [n; 32];
                let account_key = AccountKey::try_from(&RootIdentity::from(&root_entropy))
                    .expect("Invalid root identity");
                AcctPrivKeysFromRootEntropy {
                    root_entropy,
                    view_private_key: account_key.view_private_key().to_bytes(),
                    spend_private_key: account_key.spend_private_key().to_bytes(),
                }
            })
            .collect::<Vec<_>>()
    })
    .expect("Unable to write test vectors");

    write_jsonl("../vectors", || {
        (0..10)
            .map(|n| {
                let account_key = AccountKey::try_from(&RootIdentity::from(&[n; 32]))
                    .expect("Invalid root identity");
                let subaddress = account_key.default_subaddress();
                DefaultSubaddrKeysFromAcctPrivKeys {
                    view_private_key: account_key.view_private_key().to_bytes(),
                    spend_private_key: account_key.spend_private_key().to_bytes(),
                    subaddress_view_private_key: account_key
                        .default_subaddress_view_private()
                        .to_bytes(),
                    subaddress_spend_private_key: account_key
                        .default_subaddress_spend_private()
                        .to_bytes(),
                    subaddress_view_public_key: subaddress.view_public_key().to_bytes(),
                    subaddress_spend_public_key: subaddress.spend_public_key().to_bytes(),
                }
            })
            .collect::<Vec<_>>()
    })
    .expect("Unable to write test vectors");

    write_jsonl("../vectors", || {
        (0..10)
            .map(|n| {
                let account_key = AccountKey::try_from(&RootIdentity::from(&[n; 32]))
                    .expect("Invalid root identity");
                let subaddress = account_key.subaddress(n as u64);
                SubaddrKeysFromAcctPrivKeys {
                    view_private_key: account_key.view_private_key().to_bytes(),
                    spend_private_key: account_key.spend_private_key().to_bytes(),
                    subaddress_index: n as u64,
                    subaddress_view_private_key: account_key
                        .subaddress_view_private(n as u64)
                        .to_bytes(),
                    subaddress_spend_private_key: account_key
                        .subaddress_spend_private(n as u64)
                        .to_bytes(),
                    subaddress_view_public_key: subaddress.view_public_key().to_bytes(),
                    subaddress_spend_public_key: subaddress.spend_public_key().to_bytes(),
                }
            })
            .collect::<Vec<_>>()
    })
    .expect("Unable to write test vectors");
}
