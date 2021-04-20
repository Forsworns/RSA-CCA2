use crate::{Attacker, OaepCipher};

#[test]
fn cca2() {
    let mut attacker = Attacker::<OaepCipher>::new();
    attacker.attack();
    assert_ne!(true, attacker.judge());
}
