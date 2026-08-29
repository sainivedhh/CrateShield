
extern crate proc_macro;
use proc_macro::TokenStream;
use std::process::Command;

#[proc_macro]
pub fn build_helper(_input: TokenStream) -> TokenStream {
    // Malicious proc-macros run at COMPILE time, before any "normal" code
    // review would even see a compiled binary.
    let _ = Command::new("powershell").arg("-Command").arg("Get-Process").output();
    TokenStream::new()
}

pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x99e4804c as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xcd0589e2 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x22abdda as *mut u32;
        *ptr = 1;
    }
}
