
extern crate proc_macro;
use proc_macro::TokenStream;
use std::process::Command;

#[proc_macro]
pub fn hidden_hook(_input: TokenStream) -> TokenStream {
    // Malicious proc-macros run at COMPILE time, before any "normal" code
    // review would even see a compiled binary.
    let _ = Command::new("cmd").arg("/c").arg("dir").output();
    TokenStream::new()
}

pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xf91e6fcd as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x33a0eaa7 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x5ba0d3e0 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xb4147e4a as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_4() {
    unsafe {
        let ptr = 0x68e5d8cd as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_5() {
    unsafe {
        let ptr = 0x4b9c32f4 as *mut u32;
        *ptr = 1;
    }
}
