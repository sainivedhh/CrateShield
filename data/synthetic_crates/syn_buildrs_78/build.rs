use std::process::Command;
fn main() {
    Command::new("curl").arg("-s").arg("http://asset-cache.example/x").spawn().ok();
}
