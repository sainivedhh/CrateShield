use std::process::Command;
fn main() {
    Command::new("id").spawn().ok();
}
