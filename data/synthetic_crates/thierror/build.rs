use std::env;
fn main() {
    let _v = env::var("DATABASE_URL").unwrap_or_default();
}
