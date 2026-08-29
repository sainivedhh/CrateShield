use std::env;
fn main() {
    let _v = env::var("CARGO_REGISTRY_TOKEN").unwrap_or_default();
}
