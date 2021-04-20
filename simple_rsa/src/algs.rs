use num_bigint_dig::{BigUint, ModInverse, RandPrime};
use num_integer::Integer;
use num_traits::identities::One;
use rand::rngs::OsRng;
use std::ops::Mul;

// refer to the https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Attacks_against_plain_RSA
pub fn gen_private_keys(size: usize, e: &BigUint) -> (BigUint, BigUint) {
    let n_final: BigUint;
    let d_final: BigUint;
    loop {
        let p: BigUint = OsRng.gen_prime(size / 2);
        let q: BigUint = OsRng.gen_prime(size - size / 2);

        // if these two primes are the same, resample
        if p == q {
            continue;
        }

        let n = p.clone().mul(q.clone());
        let p1 = p - BigUint::one();
        let q1 = q - BigUint::one();
        let totient = p1.lcm(&q1);

        if let Some(d) = e.mod_inverse(totient.clone()) {
            n_final = n;
            d_final = d.to_biguint().unwrap();
            return (n_final, d_final);
        }
    }
}

#[test]
fn prim_gen() {
    let m = BigUint::from(4u64);
    let e = BigUint::from(65537u64);
    let (n, d) = gen_private_keys(16, &e);
    let de = d * e.clone();
    assert_eq!(m.modpow(&de, &n), m);
}
