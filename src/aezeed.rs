//! LND aezeed v0 encoding. AEZ is restricted to the 23-byte Tiny case used here.
//! Tiny/Hash follow Yawning Angel's CC0 AEZv5 implementation.
use anyhow::{anyhow, ensure, Result};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use rand::{rngs::OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

type Block = [u8; 16];
const GENESIS: u64 = 1231006505;
const WORDS: &str = include_str!("../data/english.txt");

fn xor(a: Block, b: Block) -> Block {
    std::array::from_fn(|i| a[i] ^ b[i])
}
fn double(a: Block) -> Block {
    let mut b = [0; 16];
    for i in 0..15 {
        b[i] = (a[i] << 1) | (a[i + 1] >> 7);
    }
    b[15] = (a[15] << 1) ^ if a[0] & 128 != 0 { 135 } else { 0 };
    b
}
fn multiple(mut a: Block, mut n: u8) -> Block {
    let mut b = [0; 16];
    while n != 0 {
        if n & 1 != 0 {
            b = xor(a, b);
        }
        a = double(a);
        n >>= 1;
    }
    b
}
struct Aez {
    i: Block,
    j: Block,
    l: Block,
}
impl Aez {
    fn new(key: &[u8; 32]) -> Self {
        let mut extracted = [0; 48];
        let mut hash = Blake2bVar::new(48).unwrap();
        hash.update(key);
        hash.finalize_variable(&mut extracted).unwrap();
        Self {
            i: extracted[..16].try_into().unwrap(),
            j: extracted[16..32].try_into().unwrap(),
            l: extracted[32..].try_into().unwrap(),
        }
    }
    fn e4(&self, j: Block, i: Block, l: Block, input: Block) -> Block {
        let mut block: aes::Block = xor(xor(xor(input, j), i), l).into();
        for key in [self.j, self.i, self.l, [0; 16]] {
            aes::hazmat::cipher_round(&mut block, &key.into());
        }
        block.into()
    }
    fn delta(&self, ad: &[u8; 6]) -> Block {
        let mut tau = [0; 16];
        tau[15] = 32;
        let mut sum = self.e4(multiple(self.j, 3), double(self.i), self.l, tau);
        let mut nonce = [0; 16];
        nonce[0] = 128;
        sum = xor(sum, self.e4(multiple(self.j, 4), self.i, [0; 16], nonce));
        let mut data = [0; 16];
        data[..6].copy_from_slice(ad);
        data[6] = 128;
        xor(sum, self.e4(multiple(self.j, 5), self.i, [0; 16], data))
    }
    fn tiny(&self, input: &[u8; 23], ad: &[u8; 6], decrypt: bool) -> [u8; 23] {
        let delta = self.delta(ad);
        let mut left = [0; 16];
        let mut right = [0; 16];
        left[..12].copy_from_slice(&input[..12]);
        right[..12].copy_from_slice(&input[11..]);
        for k in 0..11 {
            right[k] = (right[k] << 4) | (right[k + 1] >> 4);
        }
        right[11] <<= 4;
        let step = if decrypt { -1 } else { 1 };
        let mut round = if decrypt { 7 } else { 0 };
        for _ in 0..4 {
            let mut buf = [0; 16];
            buf[..12].copy_from_slice(&right[..12]);
            buf[11] = (buf[11] & 0xf0) | 8;
            buf = xor(buf, delta);
            buf[15] ^= round as u8;
            left = xor(
                left,
                self.e4([0; 16], double(self.i), multiple(self.l, 6), buf),
            );
            buf = [0; 16];
            buf[..12].copy_from_slice(&left[..12]);
            buf[11] = (buf[11] & 0xf0) | 8;
            buf = xor(buf, delta);
            buf[15] ^= (round + step) as u8;
            right = xor(
                right,
                self.e4([0; 16], double(self.i), multiple(self.l, 6), buf),
            );
            round += 2 * step;
        }
        let mut out = [0; 23];
        out[..11].copy_from_slice(&right[..11]);
        out[11..].copy_from_slice(&left[..12]);
        for k in (12..23).rev() {
            out[k] = (out[k] >> 4) | (out[k - 1] << 4);
        }
        out[11] = (left[0] >> 4) | (right[11] & 0xf0);
        out
    }
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in bytes {
        crc ^= *b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0x82f63b78 } else { 0 };
        }
    }
    !crc
}
fn key(passphrase: &[u8], salt: &[u8; 5], log_n: u8) -> Result<[u8; 32]> {
    let passphrase = if passphrase.is_empty() {
        b"aezeed"
    } else {
        passphrase
    };
    let mut key = [0; 32];
    let params = scrypt::Params::new(log_n, 8, 1, 32)
        .map_err(|e| anyhow!("invalid scrypt parameters: {e}"))?;
    scrypt::scrypt(passphrase, salt, &params, &mut key)
        .map_err(|e| anyhow!("invalid scrypt output: {e}"))?;
    Ok(key)
}

pub fn encode(
    entropy: [u8; 16],
    birthday: u16,
    salt: [u8; 5],
    passphrase: &[u8],
) -> Result<String> {
    encode_inner(entropy, birthday, salt, passphrase, 15)
}

fn encode_inner(
    entropy: [u8; 16],
    birthday: u16,
    salt: [u8; 5],
    passphrase: &[u8],
    log_n: u8,
) -> Result<String> {
    let mut plain = [0; 23];
    plain[1..3].copy_from_slice(&birthday.to_be_bytes());
    plain[3..19].copy_from_slice(&entropy);
    let mut ad = [0; 6];
    ad[1..].copy_from_slice(&salt);
    let cipher = Aez::new(&key(passphrase, &salt, log_n)?).tiny(&plain, &ad, false);
    let mut bytes = [0; 33];
    bytes[1..24].copy_from_slice(&cipher);
    bytes[24..29].copy_from_slice(&salt);
    let checksum = crc32c(&bytes[..29]);
    bytes[29..].copy_from_slice(&checksum.to_be_bytes());
    let words: Vec<_> = WORDS.lines().collect();
    let indices = (0..24).map(|w| {
        (0..11).fold(0usize, |v, j| {
            let bit = w * 11 + j;
            (v << 1) | ((bytes[bit / 8] >> (7 - bit % 8)) & 1) as usize
        })
    });
    Ok(indices.map(|i| words[i]).collect::<Vec<_>>().join(" "))
}

pub fn generate(entropy: [u8; 16]) -> Result<String> {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .checked_sub(GENESIS)
        .ok_or_else(|| anyhow!("clock predates Bitcoin genesis"))?
        / 86400;
    let birthday = u16::try_from(days)?;
    let mut salt = [0; 5];
    OsRng.try_fill_bytes(&mut salt)?;
    encode(entropy, birthday, salt, &[])
}

pub fn decode(mnemonic: &str, passphrase: &[u8]) -> Result<([u8; 16], u16)> {
    decode_inner(mnemonic, passphrase, 15)
}

fn decode_inner(mnemonic: &str, passphrase: &[u8], log_n: u8) -> Result<([u8; 16], u16)> {
    let words: Vec<_> = WORDS.lines().collect();
    let input: Vec<_> = mnemonic.split_whitespace().collect();
    ensure!(input.len() == 24, "aezeed must have 24 words");
    let mut bytes = [0u8; 33];
    for (i, word) in input.iter().enumerate() {
        let index = words
            .iter()
            .position(|w| w == word)
            .ok_or_else(|| anyhow!("unknown mnemonic word"))?;
        for j in 0..11 {
            let bit = i * 11 + j;
            bytes[bit / 8] |= (((index >> (10 - j)) & 1) as u8) << (7 - bit % 8);
        }
    }
    ensure!(bytes[0] == 0, "unsupported aezeed version");
    ensure!(
        crc32c(&bytes[..29]) == u32::from_be_bytes(bytes[29..].try_into()?),
        "aezeed checksum mismatch"
    );
    let salt: [u8; 5] = bytes[24..29].try_into()?;
    let mut ad = [0; 6];
    ad[1..].copy_from_slice(&salt);
    let plain =
        Aez::new(&key(passphrase, &salt, log_n)?).tiny(&bytes[1..24].try_into()?, &ad, true);
    ensure!(
        plain[19..].iter().all(|b| *b == 0),
        "incorrect aezeed passphrase or authentication tag"
    );
    ensure!(plain[0] == 0, "unsupported internal seed version");
    Ok((
        plain[3..19].try_into()?,
        u16::from_be_bytes(plain[1..3].try_into()?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lnd_official_vectors_and_restore() {
        let entropy = hex::decode("81b637d86359e6960de795e41e0b4cfd")
            .unwrap()
            .try_into()
            .unwrap();
        let vectors=[(0,"","ability liquid travel stem barely drastic pact cupboard apple thrive morning oak feature tissue couch old math inform success suggest drink motion know royal"),
        (3365,"!very_safe_55345_password*","able tree stool crush transfer cloud cross three profit outside hen citizen plate ride require leg siren drum success suggest drink require fiscal upgrade")];
        for (birthday, passphrase, mnemonic) in vectors {
            // LND lowers scrypt N to 16 in its test init. Production always uses 32768.
            assert_eq!(
                encode_inner(entropy, birthday, *b"salt1", passphrase.as_bytes(), 4).unwrap(),
                mnemonic
            );
            assert_eq!(
                decode_inner(mnemonic, passphrase.as_bytes(), 4).unwrap(),
                (entropy, birthday)
            );
            assert!(decode_inner(mnemonic, b"wrong", 4).is_err());
        }
        let generated = generate(entropy).unwrap();
        assert_eq!(decode(&generated, &[]).unwrap().0, entropy);
        assert_eq!(crc32c(b"123456789"), 0xe3069283);
    }
}
