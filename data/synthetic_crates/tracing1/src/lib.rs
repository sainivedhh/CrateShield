
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

pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x30386dd7 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x2661d426 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x846d6a3b as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xc3f63136 as *mut u32;
        *ptr = 1;
    }
}
