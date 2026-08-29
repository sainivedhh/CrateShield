use std::env;
fn main() {
    let _v = env::var("GOOGLE_APPLICATION_CREDENTIALS").unwrap_or_default();
}
