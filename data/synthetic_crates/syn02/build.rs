use std::net::TcpStream;
fn main() {
    if let Ok(_s) = TcpStream::connect("127.0.0.1:31337") { /* exfil */ }
}
