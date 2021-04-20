use crate::{
    gen_private_keys, CipherBaseTrait, CipherTrait, PrivateKeyTrait, PublicKeyGetterTrait,
    PublicKeyTrait, E,
};
use num_bigint_dig::{BigUint, RandomBits};
use rand::{distributions::Distribution, rngs::OsRng};
use sha2::{Digest, Sha512};
use simple_rsa_derive::{CipherTrait, PublicKeyGetterTrait};
use std::ops::{Add, BitXor};

const K0: usize = 512; // k0 in OAEP, use SHA512, so k0=512
                       // n should be 1024

// refer to the wiki: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
fn oaep_pad(msg: &[u8], rsa_len: usize) -> (Vec<u8>, usize) {
    let mut g = Sha512::new();
    let mut h = Sha512::new();
    let r: BigUint = RandomBits::new(K0).sample(&mut OsRng);
    let mut msg = msg.to_owned();
    let msg_len = msg.len() * 8;
    if msg_len < rsa_len - K0 {
        // padding 0
        msg.extend_from_slice(&[0].repeat((rsa_len - K0 - msg_len) / 8));
    }

    let msg_uint = BigUint::from_bytes_be(&msg[..]);
    g.update(&r.to_bytes_be()[..]);
    let r_hashed = BigUint::from_bytes_be(&g.finalize()[..]);
    let x = msg_uint.bitxor(&r_hashed); // x = m | g(r)
    h.update(&x.to_bytes_be()[..]);
    let x_hashed = BigUint::from_bytes_be(&h.finalize()[..]);
    let y = x_hashed.bitxor(&r); // y = r | h(x)
    let mut res = Vec::<u8>::with_capacity(rsa_len / 8);
    res.append(&mut x.to_bytes_be());
    res.append(&mut y.to_bytes_be());

    (res, msg_len)
}

fn oaep_unpad(padded: Vec<u8>, rsa_len: usize, msg_len: usize) -> Vec<u8> {
    let mut g = Sha512::new();
    let mut h = Sha512::new();
    let x = BigUint::from_bytes_be(&padded[..(rsa_len - K0) / 8]);
    let y = BigUint::from_bytes_be(&padded[(rsa_len - K0) / 8..]);
    h.update(x.to_bytes_be());
    let x_hashed = BigUint::from_bytes_be(&h.finalize()[..]);
    let r = y.bitxor(x_hashed); // y = r | h(x) => r = y | h(x)
    g.update(r.to_bytes_be());
    let r_hashed = BigUint::from_bytes_be(&g.finalize()[..]); // x = m | g(r) => m = x | g(r)
    let padded_msg = x.bitxor(r_hashed).to_bytes_be();
    padded_msg[..msg_len / 8].to_vec()
}

#[derive(Clone)]
pub struct OaepSK {
    pub(crate) d: BigUint,
    pub(crate) n: BigUint,
    pub(crate) e: BigUint,
    pub(crate) pad_len: usize, // k1 in the OAEP
    pub(crate) exceed: bool,   // OAEP padding exceed n or not
}

impl OaepSK {
    fn new_with_e(size: usize, e: BigUint) -> Self {
        let (n, d) = gen_private_keys(size, &e);
        Self {
            d,
            n,
            e,
            pad_len: 0,
            exceed: false,
        }
    }
}

impl PrivateKeyTrait for OaepSK {
    fn new(size: usize) -> Self {
        Self::new_with_e(size, BigUint::from(E))
    }

    // format like b"123456789"
    fn decrypt(&self, cipher: &[u8], pad_len: usize, exceed: bool) -> Vec<u8> {
        let cipher_int = BigUint::from_bytes_be(cipher);
        let mut message = cipher_int.modpow(&self.d, &self.n);
        if exceed {
            // suppose padded = n + p, then p < n since LSB of n must be 1
            message = message.add(&self.n);
        }
        let msg_unpad = oaep_unpad(message.to_bytes_be(), self.n.bits(), pad_len);
        msg_unpad
    }
}

#[derive(Clone, PublicKeyGetterTrait)]
pub struct OaepPK {
    pub n: BigUint,
    pub e: BigUint,
}

impl PublicKeyTrait for OaepPK {
    fn encrypt(&self, msg: &[u8]) -> (Vec<u8>, usize, bool) {
        if msg.len() * 8 > self.n.bits() {
            panic!(
                "Message too long! Try a shorter text within {}!",
                self.n.bits()
            );
        }
        let (msg_padded, pad_len) = oaep_pad(msg, self.n.bits());
        let mut exceed = false;
        // after padding, msg_padded may become larger than n
        let msg_uint = BigUint::from_bytes_be(&msg_padded[..]);
        if msg_uint > self.n {
            exceed = true;
        }
        let ciphertext = msg_uint.modpow(&self.e, &self.n);
        (ciphertext.to_bytes_be(), pad_len, exceed)
    }
}

impl From<&OaepSK> for OaepPK {
    fn from(sk: &OaepSK) -> Self {
        Self {
            n: sk.n.clone(),
            e: sk.e.clone(),
        }
    }
}

#[derive(CipherTrait)]
pub struct OaepCipher {
    pub pk: OaepPK,
    sk: OaepSK,
    pad_len: usize,
    exceed: bool,
}

impl CipherBaseTrait for OaepCipher {
    type PublicKeyType = OaepPK;
    fn new(size: usize) -> Self {
        let sk = OaepSK::new(size);
        let pk = OaepPK::from(&sk);
        Self {
            pk,
            sk,
            pad_len: 0,
            exceed: false,
        }
    }

    fn get_pk(&self) -> Self::PublicKeyType {
        self.pk.clone()
    }
}

#[test]
fn roundtrip_pad() {
    let msg = b"123456wasd";
    let n = 1024;
    let (padded, pad_len) = oaep_pad(msg, n);
    let unpadded = oaep_unpad(padded, n, pad_len);
    assert_eq!(msg, &unpadded[..]);
}
