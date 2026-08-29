use std::env;
fn main() {
    let _v = env::var("DOCKER_PASSWORD").unwrap_or_default();
}
