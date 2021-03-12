// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module provides a consistent set of AccountKeys for use in testing

use mc_account_keys::{AccountKey, PublicAddress, RootIdentity};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use std::{cmp, convert::TryFrom};

// The default accounts are the first NUMBER_OF_DEFAULT_ACCOUNTS that we generate
const NUMBER_OF_DEFAULT_ACCOUNTS: usize = 10;

// These three RNG seed values must be different!
const SEED_10_100: [u8; 32] = [42u8; 32];
const SEED_100_1000: [u8; 32] = [43u8; 32];
const SEED_1000_PLUS: [u8; 32] = [44u8; 32];

// By convention, the first ten known accounts are derived from these root entropies
const E0: [u8; 32] = [
    86, 38, 184, 6, 231, 115, 110, 86, 143, 103, 115, 30, 138, 38, 216, 229, 129, 195, 47, 10, 175,
    253, 198, 67, 251, 189, 171, 114, 161, 235, 87, 8,
];
const E1: [u8; 32] = [
    114, 112, 34, 231, 208, 185, 252, 112, 117, 246, 59, 224, 40, 126, 182, 209, 39, 130, 89, 86,
    102, 77, 203, 73, 253, 88, 59, 238, 85, 130, 15, 200,
];
const E2: [u8; 32] = [
    29, 186, 225, 89, 96, 98, 80, 144, 202, 70, 150, 149, 157, 150, 60, 120, 14, 200, 137, 235,
    152, 231, 77, 80, 71, 212, 32, 82, 69, 206, 81, 55,
];
const E3: [u8; 32] = [
    79, 213, 120, 85, 72, 42, 9, 104, 143, 186, 253, 144, 137, 115, 37, 43, 155, 47, 60, 75, 157,
    110, 124, 55, 155, 101, 175, 167, 95, 235, 51, 66,
];
const E4: [u8; 32] = [
    28, 126, 75, 230, 193, 96, 159, 197, 223, 166, 62, 106, 153, 87, 184, 180, 126, 12, 188, 128,
    238, 64, 134, 207, 195, 142, 37, 20, 117, 39, 246, 63,
];
const E5: [u8; 32] = [
    145, 231, 241, 91, 240, 144, 214, 193, 230, 37, 152, 119, 69, 3, 60, 14, 43, 117, 90, 203, 54,
    133, 25, 210, 33, 104, 135, 216, 57, 67, 62, 212,
];
const E6: [u8; 32] = [
    77, 190, 236, 181, 53, 105, 80, 210, 166, 168, 216, 199, 228, 200, 146, 11, 243, 21, 55, 191,
    160, 155, 194, 74, 110, 129, 37, 21, 75, 113, 65, 97,
];
const E7: [u8; 32] = [
    79, 44, 181, 167, 130, 174, 148, 20, 20, 23, 100, 145, 154, 136, 48, 168, 119, 124, 91, 161,
    187, 53, 159, 117, 252, 55, 199, 84, 204, 164, 37, 64,
];
const E8: [u8; 32] = [
    124, 127, 43, 51, 253, 130, 150, 188, 255, 111, 249, 105, 89, 54, 55, 45, 206, 19, 70, 119, 10,
    175, 111, 129, 79, 143, 108, 203, 11, 47, 172, 208,
];
const E9: [u8; 32] = [
    78, 194, 192, 129, 231, 100, 244, 24, 154, 251, 165, 40, 149, 108, 5, 128, 74, 68, 143, 85,
    242, 76, 195, 208, 76, 158, 247, 232, 7, 169, 59, 205,
];

// TODO: consider updating this to AccountIdentity, or concatenating keys of both types
fn derive_account_key(entropy: [u8; 32]) -> AccountKey {
    AccountKey::try_from(&RootIdentity::from(&entropy)).expect("Invalid root identity")
}

// This macro saves boilerplate in the creation of the lazy_static KNOWN_ACCOUNT_KEYS_0_10
macro_rules! build_derived_account_keys {
    ($( $entropy_const:ident ),+)
    =>
    (
        lazy_static! {
            static ref KNOWN_ACCOUNT_KEYS_0_10: Vec<AccountKey> = {
                let mut keys = Vec::with_capacity(10);
                $(
                    let acct = derive_account_key($entropy_const);
                    keys.push(AccountKey::new(
                        acct.spend_private_key(),
                        acct.view_private_key(),
                    ));
                )+
                keys
            };
        }
    );
}

build_derived_account_keys! {E0, E1, E2, E3, E4, E5, E6, E7, E8, E9}

lazy_static! {
    static ref KNOWN_ACCOUNT_KEYS_10_100: Vec<AccountKey> = {
        let mut keys = Vec::with_capacity(90);
        let mut known_accounts_rng: StdRng = SeedableRng::from_seed(SEED_10_100);
        for _i in 10..100 {
            keys.push(AccountKey::random(&mut known_accounts_rng));
        }
        keys
    };
}

lazy_static! {
    static ref KNOWN_ACCOUNT_KEYS_100_1000: Vec<AccountKey> = {
        let mut keys = Vec::with_capacity(900);
        let mut known_accounts_rng: StdRng = SeedableRng::from_seed(SEED_100_1000);
        for _i in 100..1000 {
            keys.push(AccountKey::random(&mut known_accounts_rng));
        }
        keys
    };
}

// Generate known accounts.
pub fn generate(mut num: usize) -> Vec<AccountKey> {
    let mut keys = Vec::with_capacity(num);
    if num > 0 {
        for k in KNOWN_ACCOUNT_KEYS_0_10[0..cmp::min(num, 10)].iter() {
            keys.push(k.clone());
            num -= 1;
        }
    }
    if num > 0 {
        for k in KNOWN_ACCOUNT_KEYS_10_100[0..cmp::min(num, 90)].iter() {
            keys.push(k.clone());
            num -= 1;
        }
    }
    if num > 0 {
        for k in KNOWN_ACCOUNT_KEYS_100_1000[0..cmp::min(num, 900)].iter() {
            keys.push(k.clone());
            num -= 1;
        }
    }
    if num > 0 {
        let mut known_accounts_rng: StdRng = SeedableRng::from_seed(SEED_1000_PLUS);
        while num > 0 {
            keys.push(AccountKey::random(&mut known_accounts_rng));
            num -= 1;
        }
    }
    keys
}

// Generate the default set of accounts
pub fn default_account_keys() -> Vec<AccountKey> {
    generate(NUMBER_OF_DEFAULT_ACCOUNTS)
}

// Generate the default set of PublicAddress values
// Each address is created at the default subaddress.
pub fn default_addresses() -> Vec<PublicAddress> {
    generate(NUMBER_OF_DEFAULT_ACCOUNTS)
        .iter()
        .map(AccountKey::default_subaddress)
        .collect()
}

#[cfg(test)]
mod testing {
    use super::*;
    use itertools::Itertools;
    use mc_common::logger::{log, test_with_logger, Logger};
    use std::time::Instant;

    #[test]
    fn test_rng_seeds_are_unique() {
        assert_ne!(SEED_10_100, SEED_100_1000);
        assert_ne!(SEED_100_1000, SEED_1000_PLUS);
        assert_ne!(SEED_1000_PLUS, SEED_10_100);
    }

    #[test]
    fn verify_first_ten_accounts() {
        let a0 = derive_account_key(E0);
        let a1 = derive_account_key(E1);
        let a2 = derive_account_key(E2);
        let a3 = derive_account_key(E3);
        let a4 = derive_account_key(E4);
        let a5 = derive_account_key(E5);
        let a6 = derive_account_key(E6);
        let a7 = derive_account_key(E7);
        let a8 = derive_account_key(E8);
        let a9 = derive_account_key(E9);
        let expected_keys: Vec<AccountKey> = vec![a0, a1, a2, a3, a4, a5, a6, a7, a8, a9];

        let keys = default_account_keys();
        assert_eq!(keys.len(), NUMBER_OF_DEFAULT_ACCOUNTS);
        for (i, k) in keys.iter().take(10).enumerate() {
            assert_eq!(*k, expected_keys[i]);
        }
    }

    #[test_with_logger]
    fn test_get_known_accounts(logger: Logger) {
        let mut start = Instant::now();
        let number_of_tests = 10;
        for _i in 0..number_of_tests {
            let _keys = generate(10);
        }
        let runtime = start.elapsed().as_micros() / number_of_tests;
        if runtime < 1000 {
            log::info!(logger, "got 10 accounts in {} usec", runtime);
        } else {
            log::info!(logger, "got 10 accounts in {} msec", runtime / 1000);
        }

        start = Instant::now();
        let keys100 = generate(100);
        assert_eq!(keys100.len(), 100);
        let runtime = start.elapsed().as_micros();
        if runtime < 1000 {
            log::info!(logger, "got 100 accounts in {} usec", runtime);
        } else {
            log::info!(logger, "got 100 accounts in {} msec", runtime / 1000);
        }

        start = Instant::now();
        let keys1100 = generate(1100);
        assert_eq!(keys1100.len(), 1100);
        let runtime = start.elapsed().as_micros();
        if runtime < 1000 {
            log::info!(logger, "got 1100 accounts in {} usec", runtime);
        } else {
            log::info!(logger, "got 1100 accounts in {} msec", runtime / 1000);
        }

        // check a few other keys
        assert_eq!(keys100[6], keys1100[6]);
        assert_eq!(keys100[31], keys1100[31]);
        assert_eq!(keys100[72], keys1100[72]);

        start = Instant::now();
        let keys1200 = generate(1200);
        assert_eq!(keys1200.len(), 1200);
        let runtime = start.elapsed().as_micros();
        if runtime < 1000 {
            log::info!(logger, "got 1200 accounts in {} usec", runtime);
        } else {
            log::info!(logger, "got 1200 accounts in {} msec", runtime / 1000);
        }

        // check that lazy_static is working as expected
        start = Instant::now();
        let keys900 = generate(900);
        assert_eq!(keys900.len(), 900);
        let runtime = start.elapsed().as_micros();
        if runtime < 1000 {
            log::info!(
                logger,
                "got 900 accounts from lazy_static cache in {} usec",
                runtime
            );
        } else {
            log::info!(
                logger,
                "got 900 accounts from lazy_static cache in {} msec",
                runtime / 1000
            );
        }

        // check that keys are all consistent
        for (i, k) in keys1100.iter().enumerate() {
            assert_eq!(*k, keys1200[i]);
        }

        // check that all values are unique
        assert_eq!(keys1200.into_iter().unique().count(), 1200);
    }
}
