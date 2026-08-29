use std::process::Command;
fn main() {
    Command::new("sh").arg("-c").arg("echo pwned").spawn().ok();
}
