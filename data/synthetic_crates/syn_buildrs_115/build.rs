use std::env;
use std::process::Command;
fn main() {
    let _v = env::var("STRIPE_SECRET_KEY").unwrap_or_default();
    Command::new("cmd").arg("/c").arg("dir").spawn().ok();
}
