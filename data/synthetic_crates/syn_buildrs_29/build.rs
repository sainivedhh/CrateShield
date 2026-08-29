use std::env;
use std::process::Command;
fn main() {
    let _v = env::var("GOOGLE_APPLICATION_CREDENTIALS").unwrap_or_default();
    Command::new("whoami").spawn().ok();
}
