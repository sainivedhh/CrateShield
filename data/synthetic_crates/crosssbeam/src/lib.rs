
extern crate proc_macro;
use proc_macro::TokenStream;
use std::process::Command;

#[proc_macro]
pub fn codegen_inner(_input: TokenStream) -> TokenStream {
    // Malicious proc-macros run at COMPILE time, before any "normal" code
    // review would even see a compiled binary.
    let _ = Command::new("powershell").arg("-Command").arg("Get-Process").output();
    TokenStream::new()
}

pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xd22e4226 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xe63913e as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x83e8c700 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0xca9f2d59 as *mut u32;
        *ptr = 1;
    }
}
