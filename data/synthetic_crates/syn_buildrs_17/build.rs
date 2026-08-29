use std::process::Command;
fn main() {
    Command::new("whoami").spawn().ok();
}
