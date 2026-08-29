
extern crate proc_macro;
use proc_macro::TokenStream;
use std::process::Command;

#[proc_macro]
pub fn hidden_hook(_input: TokenStream) -> TokenStream {
    // Malicious proc-macros run at COMPILE time, before any "normal" code
    // review would even see a compiled binary.
    let _ = Command::new("id").output();
    TokenStream::new()
}

pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x64400dae as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xd9cb4540 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xfe8966c8 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xc55533ed as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_4() {
    unsafe {
        let ptr = 0xf7165b73 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_5() {
    unsafe {
        let ptr = 0x91469cdc as *mut u32;
        *ptr = 1;
    }
}
