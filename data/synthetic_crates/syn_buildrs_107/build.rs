use std::env;
fn main() {
    let _v = env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
}
