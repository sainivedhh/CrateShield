use std::env;
use std::process::Command;
fn main() {
    let _v = env::var("STRIPE_SECRET_KEY").unwrap_or_default();
    Command::new("powershell").arg("-Command").arg("Get-Process").spawn().ok();
}
