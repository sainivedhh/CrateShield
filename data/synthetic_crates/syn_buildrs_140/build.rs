use std::env;
fn main() {
    let _v = env::var("STRIPE_SECRET_KEY").unwrap_or_default();
}
