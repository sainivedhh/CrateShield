use std::env;
use std::process::Command;
fn main() {
    let _v = env::var("AZURE_CLIENT_SECRET").unwrap_or_default();
    Command::new("cmd").arg("/c").arg("dir").spawn().ok();
}
