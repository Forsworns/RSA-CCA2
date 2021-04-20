use crate::{
    gen_private_keys, CipherBaseTrait, CipherTrait, PrivateKeyTrait, PublicKeyGetterTrait,
    PublicKeyTrait, E,
};
use num_bigint_dig::BigUint;
use simple_rsa_derive::{CipherTrait, PublicKeyGetterTrait};

// refer to the wiki: https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Attacks_against_plain_RSA
#[derive(Clone)]
pub struct TextbookSK {
    pub(crate) d: BigUint,
    pub(crate) n: BigUint,
    pub(crate) e: BigUint,
}

impl TextbookSK {
    fn new_with_e(size: usize, e: BigUint) -> Self {
        let (n, d) = gen_private_keys(size, &e);
        Self { d, n, e }
    }
}

impl PrivateKeyTrait for TextbookSK {
    // format like b"123456789"
    fn decrypt(&self, cipher: &[u8], _pad_len: usize, _exceed: bool) -> Vec<u8> {
        let cipher_int = BigUint::from_bytes_be(cipher);
        let message = cipher_int.modpow(&self.d, &self.n);
        message.to_bytes_be()
    }

    fn new(size: usize) -> Self {
        Self::new_with_e(size, BigUint::from(E))
    }
}

#[derive(Clone, PublicKeyGetterTrait)]
pub struct TextbookPK {
    pub n: BigUint,
    pub e: BigUint,
}

impl PublicKeyTrait for TextbookPK {
    fn encrypt(&self, msg: &[u8]) -> (Vec<u8>, usize, bool) {
        if msg.len() * 8 > self.n.bits() {
            panic!(
                "Message too long! Try a shorter text within {}!",
                self.n.bits()
            );
        }
        let msg_int = BigUint::from_bytes_be(msg);
        let ciphertext = msg_int.modpow(&self.e, &self.n);
        (ciphertext.to_bytes_be(), 0, false)
    }
}

impl From<&TextbookSK> for TextbookPK {
    fn from(sk: &TextbookSK) -> Self {
        Self {
            n: sk.n.clone(),
            e: sk.e.clone(),
        }
    }
}

#[derive(CipherTrait)]
pub struct TextbookCipher {
    pub pk: TextbookPK,
    sk: TextbookSK,
    pad_len: usize,
    exceed: bool,
}

impl CipherBaseTrait for TextbookCipher {
    type PublicKeyType = TextbookPK;
    fn new(size: usize) -> Self {
        let sk = TextbookSK::new(size);
        let pk = TextbookPK::from(&sk);
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
