#![allow(dead_code)]

mod oaep;
mod textbook;

use simple_rsa::{CipherBaseTrait, CipherTrait, OaepCipher, PublicKeyGetterTrait, TextbookCipher};

// only for CCA2
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockCipher, NewBlockCipher};
use aes::Aes128;
use num_bigint_dig::{BigUint, RandomBits};
use num_traits::identities::{One, Zero};
use rand::{distributions::Distribution, rngs::OsRng};
use std::ops::{Add, AddAssign, Mul, Shl};

// key and msg should be 128 bit

fn aes_encrypt(msg: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(key);
    let mut block = GenericArray::clone_from_slice(msg);
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(&mut block);
    block.as_slice().to_vec()
}

fn aes_decrypt(ciphertext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let key = GenericArray::clone_from_slice(&key);
    let mut block = GenericArray::clone_from_slice(&ciphertext);
    let cipher = Aes128::new(&key);
    cipher.decrypt_block(&mut block);
    block.as_slice().to_vec()
}

fn aes_to_128(text: BigUint) -> Vec<u8> {
    let mut text = text.to_bytes_be();
    if text.len() < 16 {
        // padding head to 128 bits
        let mut padding = vec![0; 16 - text.len()];
        padding.append(&mut text);
        padding
    } else {
        // only select the tail 128 bits
        text[text.len() - 16..].to_vec()
    }
}

struct Server<T: CipherTrait + CipherBaseTrait> {
    cipher: T,
    msg: Vec<u8>, // [u8;16]
    ciphertext: Vec<u8>,
    aes_key: Vec<u8>, // [u8;16]
    aes_key_encrypted: Vec<u8>,
}

impl<T> Server<T>
where
    T: CipherTrait + CipherBaseTrait,
{
    pub fn new() -> Self {
        let mut aes_key: BigUint = RandomBits::new(128).sample(&mut OsRng);
        if aes_key.bits() < 128 {
            aes_key = aes_key.add(BigUint::one().shl(127));
        }
        let aes_key = aes_to_128(aes_key);
        println!("The generated AES key is in fact {:?}", aes_key);

        let msg = BigUint::from_bytes_be(b"testtext");
        let msg = aes_to_128(msg);

        let ciphertext = aes_encrypt(&msg, &aes_key);
        let mut cipher = T::new(1024);
        let aes_key_encrypted = cipher.encrypt(&aes_key);
        assert_eq!(aes_key, cipher.decrypt(&aes_key_encrypted));
        // let decrypted = sk.decrypt(&encrypted);
        // assert_eq!(encrypted, decrypted);
        Self {
            cipher,
            msg,
            ciphertext,
            aes_key,
            aes_key_encrypted,
        }
    }

    // deal with encrypted aes_key and ciphertext
    pub fn oracle(&self, aes_key_encrypted: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
        let mut aes_key = self.cipher.decrypt(&aes_key_encrypted);
        aes_key = aes_key[aes_key.len() - 16..].to_vec();
        aes_decrypt(&ciphertext, &aes_key)
    }

    pub fn judge(&self, msg_guess: Vec<u8>) -> bool {
        self.msg == msg_guess
    }

    pub fn leak(&self) -> (Vec<u8>, Vec<u8>) {
        (self.ciphertext.clone(), self.aes_key_encrypted.clone())
    }
}

struct Attacker<T: CipherTrait + CipherBaseTrait> {
    ciphertext: Vec<u8>,
    server: Server<T>,
    aes_key_guess: BigUint,
    aes_key_encrypted: BigUint, // leaked C
}

impl<T> Attacker<T>
where
    T: CipherTrait + CipherBaseTrait,
{
    pub fn new() -> Self {
        let aes_key_guess = BigUint::zero();
        let server = Server::new();
        let (ciphertext, aes_key_encrypted) = server.leak();
        let aes_key_encrypted = BigUint::from_bytes_be(&aes_key_encrypted);
        Self {
            aes_key_guess,
            server,
            ciphertext,
            aes_key_encrypted,
        }
    }

    // receive encoded aes_key and ciphertext
    fn request(&self, aes_key_encrypted: Vec<u8>, wup: Vec<u8>, wup_encrypted: Vec<u8>) -> bool {
        self.server.oracle(aes_key_encrypted, wup_encrypted) == wup
    }

    fn estimator(&self, pos: usize) -> (Vec<u8>, Vec<u8>) {
        // `C_b = C*(2^{be} mod n) mod n`
        let two = BigUint::from(2u64);
        let be = BigUint::from(pos).mul(&self.server.cipher.get_pk().get_e());
        let two2be = two.modpow(&be, &self.server.cipher.get_pk().get_n()); // 2^{be}
        let mut c_b = two2be.mul(&self.aes_key_encrypted); // C * 2^{be}
        c_b = c_b.modpow(&BigUint::one(), &self.server.cipher.get_pk().get_n()); // `mod n`
        let c_b = c_b.to_bytes_be();
        let aes_key_b = BigUint::one()
            .shl(127)
            .add(self.aes_key_guess.clone().shl(pos));
        let aes_key_b = aes_to_128(aes_key_b);
        (c_b, aes_key_b)
    }

    pub fn attack(&mut self) {
        for i in 0..=127usize {
            let (c_b, aes_key_b) = self.estimator(127 - i);
            let wup = [0u8; 16].to_vec();
            let wup_encrypted = aes_encrypt(&wup, &aes_key_b); // encrypted WUP
                                                               /* println!(
                                                                   "Current estimating {}-th bit,\nc_b is {:?},\nWUP is {:?},\nWUP encrypted: {:?}\naes_key_b: {:?}",
                                                                   i, c_b, wup, wup_encrypted, aes_key_b
                                                               ); */
            if self.request(c_b, wup, wup_encrypted) {
                println!("{}-th bit should be 1", i);
                self.aes_key_guess.add_assign(BigUint::one().shl(i));
            } else {
                println!("{}-th bit should be 0", i);
            }
        }
    }

    // try to decrypt the original text
    pub fn judge(&self) -> bool {
        // do not need padding anymore
        let text_guess = aes_decrypt(&self.ciphertext, &aes_to_128(self.aes_key_guess.clone()));
        self.server.judge(text_guess)
    }
}

#[test]
fn attack_test() {
    let mut attacker = Attacker::<TextbookCipher>::new();

    let two = BigUint::from(2u64);
    let b = BigUint::from(127u64);
    let aes_key_mul = two
        .modpow(&b, &attacker.server.cipher.get_pk().get_n())
        .mul(BigUint::from_bytes_be(&attacker.server.aes_key));
    let aes_key_shift = BigUint::from_bytes_be(&attacker.server.aes_key).shl(127);
    assert_eq!(
        aes_key_mul
            .modpow(&BigUint::one(), &attacker.server.cipher.get_pk().get_n())
            .to_bytes_be(),
        aes_key_shift
            .modpow(&BigUint::one(), &attacker.server.cipher.get_pk().get_n())
            .to_bytes_be()
    );

    let c_b = aes_key_mul.modpow(
        &attacker.server.cipher.get_pk().get_e(),
        &attacker.server.cipher.get_pk().get_n(),
    );
    let c_b = c_b.to_bytes_be();
    assert_eq!(
        c_b,
        attacker.server.cipher.encrypt(&aes_key_shift.to_bytes_be())
    );
    assert_eq!(
        aes_key_shift.to_bytes_be(),
        attacker.server.cipher.decrypt(&c_b)
    );
}

#[test]
fn aes_test() {
    let mut aes_key: BigUint = RandomBits::new(128).sample(&mut OsRng);
    if aes_key.bits() < 128 {
        aes_key = aes_key.add(BigUint::one().shl(127));
    }
    let aes_key = aes_to_128(aes_key);
    let msg = BigUint::from_bytes_le(b"123456");
    let msg = aes_to_128(msg);
    println!("--AES test: The msg is {:?}, the key is {:?}", msg, aes_key);
    let ciphertext = aes_encrypt(&msg, &aes_key);
    assert_eq!(aes_decrypt(&ciphertext, &aes_key), msg);
    println!(
        "CCA2 attack succeed! The encrypted message is {:?}",
        aes_decrypt(&ciphertext, &aes_key)
    );
}
