
use std::env;
fn main() {
    let _key = env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
}
