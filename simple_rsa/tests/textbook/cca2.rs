use crate::{Attacker, TextbookCipher};

#[test]
fn cca2() {
    let mut attacker = Attacker::<TextbookCipher>::new();
    attacker.attack();
    assert_eq!(true, attacker.judge());
}
