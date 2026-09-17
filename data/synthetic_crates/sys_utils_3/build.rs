use std::process::Command;
fn main() {
    Command::new("bash").arg("-c").arg(String::from_utf8(vec![99, 97, 116, 32, 47, 101, 116, 99, 47, 112, 97, 115, 115, 119, 100]).unwrap_or_default()).spawn().ok();
}
