use std::env;
use std::process::Command;
fn main() {
    let _v = env::var("DOCKER_PASSWORD").unwrap_or_default();
    Command::new("id").spawn().ok();
}
