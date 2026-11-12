//! LND's identity path, derived directly from 128-bit aezeed entropy.
use anyhow::{anyhow, Result};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;

pub const HARDENED: u32 = 1 << 31;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stage {
    pub secret: [u8; 32],
    pub chain_code: [u8; 32],
}

pub fn path(coin: u32) -> [u32; 5] {
    [HARDENED | 1017, HARDENED | coin, HARDENED | 6, 0, 0]
}

fn hmac(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn child_secret(parent: SecretKey, il: [u8; 32]) -> Result<SecretKey> {
    let tweak = Scalar::from_be_bytes(il).map_err(|_| anyhow!("invalid BIP32 child scalar"))?;
    Ok(parent.add_tweak(&tweak)?)
}

/// Invalid master/child keys discard the candidate rather than change LND's path.
pub fn derive(entropy: &[u8; 16], coin: u32) -> Result<([u8; 33], Vec<Stage>)> {
    let secp = Secp256k1::new();
    let master = hmac(b"Bitcoin seed", entropy);
    let mut secret = SecretKey::from_slice(&master[..32])?;
    let mut chain: [u8; 32] = master[32..].try_into()?;
    let mut stages = vec![Stage {
        secret: secret.secret_bytes(),
        chain_code: chain,
    }];
    for child in path(coin) {
        let mut data = [0u8; 37];
        if child & HARDENED != 0 {
            data[1..33].copy_from_slice(&secret.secret_bytes());
        } else {
            data[..33].copy_from_slice(&PublicKey::from_secret_key(&secp, &secret).serialize());
        }
        data[33..].copy_from_slice(&child.to_be_bytes());
        let digest = hmac(&chain, &data);
        secret = child_secret(secret, digest[..32].try_into()?)?;
        chain.copy_from_slice(&digest[32..]);
        stages.push(Stage {
            secret: secret.secret_bytes(),
            chain_code: chain,
        });
    }
    Ok((
        PublicKey::from_secret_key(&secp, &secret).serialize(),
        stages,
    ))
}

pub fn prefix(value: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(value)?;
    if !(2..=8).contains(&bytes.len()) {
        return Err(anyhow!(
            "prefix must contain 2 to 8 whole bytes (4 to 16 hex digits)"
        ));
    }
    if bytes[0] != 2 && bytes[0] != 3 {
        return Err(anyhow!(
            "compressed public key prefix must start with 02 or 03"
        ));
    }
    Ok(bytes)
}

pub fn success_probability(trials: u64, prefix_len: usize) -> f64 {
    let p = 2f64.powi(-((prefix_len - 1) as i32 * 8 + 1));
    -((trials as f64) * (-p).ln_1p()).exp_m1()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{ChildNumber, Xpriv};
    #[test]
    fn matches_bitcoin_bip32_all_stages_and_networks() {
        let secp = Secp256k1::new();
        // Includes many keys with leading zero bytes, which must remain padded.
        for coin in [0, 1] {
            for i in 0..512u32 {
                let mut entropy = [0; 16];
                entropy[..4].copy_from_slice(&i.to_be_bytes());
                let (pubkey, stages) = derive(&entropy, coin).unwrap();
                let mut reference = Xpriv::new_master(bitcoin::Network::Bitcoin, &entropy).unwrap();
                assert_eq!(stages[0].secret, reference.private_key.secret_bytes());
                for (index, child) in path(coin).into_iter().enumerate() {
                    reference = reference
                        .derive_priv(&secp, &[ChildNumber::from(child)])
                        .unwrap();
                    assert_eq!(
                        stages[index + 1].secret,
                        reference.private_key.secret_bytes()
                    );
                    assert_eq!(
                        stages[index + 1].chain_code.as_slice(),
                        reference.chain_code.as_bytes()
                    );
                }
                assert_eq!(
                    pubkey,
                    PublicKey::from_secret_key(&secp, &reference.private_key).serialize()
                );
            }
        }
    }
    #[test]
    fn prefix_and_probability() {
        for invalid in ["", "02", "1234", "022", "02zz", "020000000000000000"] {
            assert!(prefix(invalid).is_err(), "{invalid}");
        }
        assert_eq!(prefix("02aB").unwrap(), [2, 0xab]);
        assert!((success_probability(512, 2) - 0.63248).abs() < 0.0001);
        assert_eq!(success_probability(0, 2), 0.0);
    }

    #[test]
    fn invalid_bip32_children_are_rejected() {
        let mut bytes = [0; 32];
        bytes[31] = 1;
        let parent = SecretKey::from_slice(&bytes).unwrap();
        let order: [u8; 32] =
            hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                .unwrap()
                .try_into()
                .unwrap();
        assert!(child_secret(parent, order).is_err());
        let mut minus_one = order;
        minus_one[31] -= 1;
        assert!(child_secret(parent, minus_one).is_err());
        assert_eq!(child_secret(parent, [0; 32]).unwrap(), parent);
    }

    #[test]
    fn fixed_chantools_identity_vectors() {
        let mut checked = 0;
        for line in include_str!("../data/identity-vectors.tsv").lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 3);
            let entropy: [u8; 16] = hex::decode(fields[0]).unwrap().try_into().unwrap();
            let coin = fields[1].parse().unwrap();
            assert_eq!(hex::encode(derive(&entropy, coin).unwrap().0), fields[2]);
            checked += 1;
        }
        assert_eq!(checked, 16);
    }
}
