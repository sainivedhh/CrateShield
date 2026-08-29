use std::env;
use std::process::Command;
fn main() {
    let _v = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
    Command::new("whoami").spawn().ok();
}
