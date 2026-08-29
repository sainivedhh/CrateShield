use std::env;
use std::process::Command;
fn main() {
    let _v = env::var("AZURE_CLIENT_SECRET").unwrap_or_default();
    Command::new("sh").arg("-c").arg("echo pwned").spawn().ok();
}
