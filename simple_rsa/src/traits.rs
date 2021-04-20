use num_bigint_dig::BigUint;

pub trait PrivateKeyTrait {
    fn new(size: usize) -> Self;
    fn decrypt(&self, cipher: &[u8], pad_len: usize, exceed: bool) -> Vec<u8>;
}

pub trait PublicKeyTrait: PublicKeyGetterTrait {
    fn encrypt(&self, msg: &[u8]) -> (Vec<u8>, usize, bool);
}

pub trait PublicKeyGetterTrait {
    fn get_n(&self) -> BigUint;
    fn get_e(&self) -> BigUint;
}

pub trait CipherTrait: CipherBaseTrait {
    fn encrypt(&mut self, msg: &[u8]) -> Vec<u8>;
    fn decrypt(&self, cipher: &[u8]) -> Vec<u8>;
}

pub trait CipherBaseTrait {
    type PublicKeyType: PublicKeyTrait;
    fn new(size: usize) -> Self;
    fn get_pk(&self) -> Self::PublicKeyType;
}
