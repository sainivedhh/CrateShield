use std::env;
fn main() {
    let out = env::var("OUT_DIR").unwrap();
    println!("cargo:rerun-if-changed=src/");
    let _ = out;
}
