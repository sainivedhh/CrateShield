use std::env;
fn main() {
    let _v = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
}
