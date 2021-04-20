use crate::{CipherBaseTrait, CipherTrait, TextbookCipher};

fn roundtrip(msg: &[u8]) {
    let mut cipher = TextbookCipher::new(1024);
    let encrypted = cipher.encrypt(msg);
    let decrypted = cipher.decrypt(&encrypted);
    assert_eq!(msg, &decrypted[..]);
}

#[test]
fn roundtrip1() {
    roundtrip(b"123456789");
}

#[test]
fn roundtrip2() {
    roundtrip(b"thisisamessage");
}

#[test]
#[should_panic(expected = "Message too long! Try a shorter text within 10!")]
fn should_panic() {
    let msg = b"123456789";
    let mut cipher = TextbookCipher::new(10);
    cipher.encrypt(msg);
}
