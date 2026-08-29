use std::env;
fn main() {
    let _v = env::var("GITHUB_TOKEN").unwrap_or_default();
}
