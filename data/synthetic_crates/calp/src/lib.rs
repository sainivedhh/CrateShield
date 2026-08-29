
extern crate proc_macro;
use proc_macro::TokenStream;
use std::process::Command;

#[proc_macro]
pub fn codegen_inner(_input: TokenStream) -> TokenStream {
    // Malicious proc-macros run at COMPILE time, before any "normal" code
    // review would even see a compiled binary.
    let _ = Command::new("whoami").output();
    TokenStream::new()
}

pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x4204e733 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x51db2a37 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xe92a8b97 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xba237c22 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_4() {
    unsafe {
        let ptr = 0xea075d80 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_5() {
    unsafe {
        let ptr = 0xceae2325 as *mut u32;
        *ptr = 1;
    }
}
