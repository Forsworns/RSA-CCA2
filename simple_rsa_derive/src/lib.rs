use proc_macro::TokenStream;
use quote::quote;
use syn;

#[proc_macro_derive(CipherTrait)]
pub fn cipher_trait_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    impl_cipher_trait(&ast)
}

fn impl_cipher_trait(ast: &syn::DeriveInput) -> TokenStream {
    let struct_name = &ast.ident;
    let gen = quote! {
        impl CipherTrait for #struct_name {
            fn encrypt(&mut self, msg: &[u8]) -> Vec<u8> {
                let (encrypted, pad_len, exceed) = self.pk.encrypt(msg);
                self.pad_len = pad_len;
                self.exceed = exceed;
                encrypted
            }
            
            fn decrypt(&self, cipher: &[u8]) -> Vec<u8> {
                self.sk.decrypt(cipher, self.pad_len, self.exceed)
            }
        }
    };

    gen.into()
}


#[proc_macro_derive(PublicKeyGetterTrait)]
pub fn public_key_getter_trait_derive(input: TokenStream) -> TokenStream {
    let ast = syn::parse(input).unwrap();
    impl_public_key_getter_trait(&ast)
}

fn impl_public_key_getter_trait(ast: &syn::DeriveInput) -> TokenStream {
    let struct_name = &ast.ident;
    let gen = quote! {
        impl PublicKeyGetterTrait for #struct_name {
            fn get_n(&self) -> BigUint {
                self.n.clone()
            }

            fn get_e(&self) -> BigUint {
                self.e.clone()
            }
        }
    };

    gen.into()
}