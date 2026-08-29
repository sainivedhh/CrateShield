use std::env;
fn main() {
    let _v = env::var("NPM_TOKEN").unwrap_or_default();
}
