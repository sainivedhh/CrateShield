use std::env;
fn main() {
    let _v = env::var("SSH_AUTH_SOCK").unwrap_or_default();
}
