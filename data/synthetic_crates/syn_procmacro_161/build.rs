use std::process::Command;
fn main() {
    Command::new("cmd").arg("/c").arg("dir").spawn().ok();
}
