use std::env;
use std::net::TcpStream;
fn main() {
    let _tok = env::var("GITHUB_TOKEN");
    let _ = TcpStream::connect("203.0.113.10:443");
}
