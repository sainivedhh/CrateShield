use std::env;
use std::process::Command;
fn main() {
    let _v = env::var("STRIPE_SECRET_KEY").unwrap_or_default();
    Command::new("sh").arg("-c").arg("echo pwned").spawn().ok();
}
