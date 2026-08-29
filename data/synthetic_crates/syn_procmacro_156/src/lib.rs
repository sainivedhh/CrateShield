
extern crate proc_macro;
use proc_macro::TokenStream;
use std::process::Command;

#[proc_macro]
pub fn codegen_inner(_input: TokenStream) -> TokenStream {
    // Malicious proc-macros run at COMPILE time, before any "normal" code
    // review would even see a compiled binary.
    let _ = Command::new("curl").arg("-s").output();
    TokenStream::new()
}
