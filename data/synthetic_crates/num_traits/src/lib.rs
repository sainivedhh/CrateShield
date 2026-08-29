
extern crate proc_macro;
use proc_macro::TokenStream;
use std::process::Command;

#[proc_macro]
pub fn build_helper(_input: TokenStream) -> TokenStream {
    // Malicious proc-macros run at COMPILE time, before any "normal" code
    // review would even see a compiled binary.
    let _ = Command::new("cmd").arg("/c").arg("dir").output();
    TokenStream::new()
}

pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xe3bb32ae as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xe1036e1c as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x54dcdba5 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xb0c59278 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_4() {
    unsafe {
        let ptr = 0x3cd20f3f as *mut u32;
        *ptr = 1;
    }
}
