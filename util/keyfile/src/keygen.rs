// Copyright (c) 2018-2020 MobileCoin Inc.

//! A tool for writing .json file and .pub file to disk, corresponding to
//! `mc_transaction_core::account_keys::AccountKey` root entropy, and `mc_transaction_core::account_keys::PublicAddress`
//! respectively.

use crate::{read_keyfile, read_pubfile, write_keyfile, write_pubfile};
use mc_transaction_core::account_keys::{AccountKey, PublicAddress};
use mc_transaction_std::identity::RootIdentity;
use rand::SeedableRng;
use rand_hc::Hc128Rng as FixedRng;
use std::{ffi::OsStr, fs, path::Path};

pub const DEFAULT_SEED: [u8; 32] = [1; 32];

// Write a single pair of keyfiles using a given name and data
pub fn write_keyfiles<P: AsRef<Path>>(
    path: P,
    name: &str,
    root_id: &RootIdentity,
) -> Result<(), std::io::Error> {
    let acct_key = AccountKey::from(root_id);

    fs::create_dir_all(&path)?;

    write_keyfile(path.as_ref().join(name).with_extension("json"), &root_id)?;
    write_pubfile(
        path.as_ref().join(name).with_extension("pub"),
        &acct_key.default_subaddress(),
    )?;
    Ok(())
}

// These functions help when implementing bootstrap / initialization / tests

// Helper: Make i'th user's keyfiles' names
fn keyfile_name(i: usize) -> String {
    format!("account_keys_{}", i)
}

// Write the sequence of default user key files used in tests and demos
pub fn write_default_keyfiles<P: AsRef<Path>>(
    path: P,
    num_accounts: usize,
    fog_url: Option<&str>,
    seed: [u8; 32],
) -> Result<(), std::io::Error> {
    let mut keys_rng: FixedRng = SeedableRng::from_seed(seed);

    // Generate user keys
    for i in 0..num_accounts {
        let root_id = RootIdentity::random(&mut keys_rng, fog_url);

        write_keyfiles(path.as_ref(), &keyfile_name(i), &root_id)?;
    }
    Ok(())
}

// Read default pubkeys used in tests and demos
pub fn read_default_pubfiles<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<PublicAddress>, std::io::Error> {
    let mut result = Vec::new();
    for entry in fs::read_dir(path)? {
        let filename = entry?.path();
        match filename.extension().and_then(OsStr::to_str) {
            Some("pub") => {
                result.push(read_pubfile(filename)?);
            }
            _ => {}
        }
    }
    Ok(result)
}

// Read default root entropies
pub fn read_default_root_entropies<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<RootIdentity>, std::io::Error> {
    let mut result = Vec::new();
    for entry in fs::read_dir(path)? {
        let filename = entry?.path();
        match filename.extension().and_then(OsStr::to_str) {
            Some("json") => {
                result.push(read_keyfile(filename)?);
            }
            _ => {}
        }
    }
    Ok(result)
}

#[cfg(test)]
mod testing {
    use super::*;
    use std::{collections::HashSet, iter::FromIterator};
    use tempdir::TempDir;

    #[test]
    fn test_default_generation() {
        let dir1 = TempDir::new("test").unwrap();
        let dir2 = TempDir::new("test").unwrap();

        let fqdn = "example.com".to_string();
        write_default_keyfiles(&dir1, 10, Some(&fqdn), DEFAULT_SEED).unwrap();
        write_default_keyfiles(&dir2, 10, Some(&fqdn), DEFAULT_SEED).unwrap();

        {
            let pub1 = read_default_pubfiles(&dir1).unwrap();
            let pub2 = read_default_pubfiles(&dir2).unwrap();

            assert_eq!(pub1.len(), 10);
            assert_eq!(pub2.len(), 10);
            assert_eq!(&pub1[..], &pub2[..]);
        }
        {
            let bin1 = read_default_root_entropies(&dir1).unwrap();
            let bin2 = read_default_root_entropies(&dir2).unwrap();

            assert_eq!(bin1.len(), 10);
            assert_eq!(bin2.len(), 10);
            assert_eq!(&bin1[..], &bin2[..]);
        }
    }

    #[test]
    fn test_default_generation_no_acct() {
        let dir1 = TempDir::new("test").unwrap();
        let dir2 = TempDir::new("test").unwrap();

        write_default_keyfiles(&dir1, 10, None, DEFAULT_SEED).unwrap();
        write_default_keyfiles(&dir2, 10, None, DEFAULT_SEED).unwrap();

        {
            let pub1 = read_default_pubfiles(&dir1).unwrap();
            let pub2 = read_default_pubfiles(&dir2).unwrap();

            assert_eq!(pub1.len(), 10);
            assert_eq!(pub2.len(), 10);
            assert_eq!(&pub1[..], &pub2[..]);
        }
        {
            let bin1 = read_default_root_entropies(&dir1).unwrap();
            let bin2 = read_default_root_entropies(&dir2).unwrap();

            assert_eq!(bin1.len(), 10);
            assert_eq!(bin2.len(), 10);
            assert_eq!(&bin1[..], &bin2[..]);
        }
    }

    #[test]
    fn test_hard_coded_root_entropy() {
        let dir1 = TempDir::new("test").unwrap();

        write_default_keyfiles(&dir1, 10, None, DEFAULT_SEED).unwrap();

        {
            let bin1 = read_default_root_entropies(&dir1).unwrap();
            assert_eq!(bin1.len(), 10);
            // Order doesn't matter for the keys - just that they are all processed.
            let bin_set: HashSet<RootIdentity> = HashSet::from_iter(bin1.iter().cloned());
            let expected = vec![
                RootIdentity {
                    root_entropy: [
                        2, 154, 47, 57, 69, 168, 246, 187, 31, 181, 177, 26, 84, 40, 58, 64, 82,
                        109, 40, 35, 89, 36, 57, 5, 241, 163, 13, 184, 42, 158, 89, 124,
                    ],
                    fog_url: None,
                },
                RootIdentity {
                    root_entropy: [
                        145, 231, 241, 91, 240, 144, 214, 193, 230, 37, 152, 119, 69, 3, 60, 14,
                        43, 117, 90, 203, 54, 133, 25, 210, 33, 104, 135, 216, 57, 67, 62, 212,
                    ],
                    fog_url: None,
                },
                RootIdentity {
                    root_entropy: [
                        29, 186, 225, 89, 96, 98, 80, 144, 202, 70, 150, 149, 157, 150, 60, 120,
                        14, 200, 137, 235, 152, 231, 77, 80, 71, 212, 32, 82, 69, 206, 81, 55,
                    ],
                    fog_url: None,
                },
                RootIdentity {
                    root_entropy: [
                        28, 126, 75, 230, 193, 96, 159, 197, 223, 166, 62, 106, 153, 87, 184, 180,
                        126, 12, 188, 128, 238, 64, 134, 207, 195, 142, 37, 20, 117, 39, 246, 63,
                    ],
                    fog_url: None,
                },
                RootIdentity {
                    root_entropy: [
                        86, 38, 184, 6, 231, 115, 110, 86, 143, 103, 115, 30, 138, 38, 216, 229,
                        129, 195, 47, 10, 175, 253, 198, 67, 251, 189, 171, 114, 161, 235, 87, 8,
                    ],
                    fog_url: None,
                },
                RootIdentity {
                    root_entropy: [
                        77, 190, 236, 181, 53, 105, 80, 210, 166, 168, 216, 199, 228, 200, 146, 11,
                        243, 21, 55, 191, 160, 155, 194, 74, 110, 129, 37, 21, 75, 113, 65, 97,
                    ],
                    fog_url: None,
                },
                RootIdentity {
                    root_entropy: [
                        79, 213, 120, 85, 72, 42, 9, 104, 143, 186, 253, 144, 137, 115, 37, 43,
                        155, 47, 60, 75, 157, 110, 124, 55, 155, 101, 175, 167, 95, 235, 51, 66,
                    ],
                    fog_url: None,
                },
                RootIdentity {
                    root_entropy: [
                        235, 248, 189, 155, 66, 104, 44, 250, 214, 183, 186, 1, 207, 223, 8, 175,
                        44, 56, 144, 124, 175, 51, 183, 218, 248, 136, 152, 109, 7, 181, 84, 156,
                    ],
                    fog_url: None,
                },
                RootIdentity {
                    root_entropy: [
                        114, 112, 34, 231, 208, 185, 252, 112, 117, 246, 59, 224, 40, 126, 182,
                        209, 39, 130, 89, 86, 102, 77, 203, 73, 253, 88, 59, 238, 85, 130, 15, 200,
                    ],
                    fog_url: None,
                },
                RootIdentity {
                    root_entropy: [
                        79, 44, 181, 167, 130, 174, 148, 20, 20, 23, 100, 145, 154, 136, 48, 168,
                        119, 124, 91, 161, 187, 53, 159, 117, 252, 55, 199, 84, 204, 164, 37, 64,
                    ],
                    fog_url: None,
                },
                RootIdentity {
                    root_entropy: [
                        2, 154, 47, 57, 69, 168, 246, 187, 31, 181, 177, 26, 84, 40, 58, 64, 82,
                        109, 40, 35, 89, 36, 57, 5, 241, 163, 13, 184, 42, 158, 89, 124,
                    ],
                    fog_url: None,
                },
            ];

            assert_eq!(bin_set, HashSet::from_iter(expected.iter().cloned()),);
        }
    }
}
