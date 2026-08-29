use std::env;
fn main() {
    let _v = env::var("AZURE_CLIENT_SECRET").unwrap_or_default();
}
