# RSA-CCA2

Attack RSA with the method from [When Textbook RSA is Used to Protect the Privacy of Hundreds of Millions of Users (arxiv.org)](http://export.arxiv.org/abs/1802.03367). 

Directory tree:

```bash
.
├── simple_rsa
│   ├── src
│   │   ├── algs.rs				# key generation algorithms
│   │   ├── lib.rs
│   │   ├── oaep.rs				# OAEP padded RSA
│   │   ├── textbook.rs			# textbook RSA
│   │   └── traits.rs 			
│   └── tests 					# testcases and CCA2 
└── simple_rsa_derive 			# procedural macros
```

To encrypt / decrypt

```rust
use crate::{CipherBaseTrait, CipherTrait, TextbookCipher};

let mut cipher = TextbookCipher::new(1024);
let encrypted = cipher.encrypt(msg);
let decrypted = cipher.decrypt(&encrypted);
assert_eq!(msg, &decrypted[..]);
```

Test CCA2, run 

```bash
cargo test textbook::cca2 -- --nocapture
```