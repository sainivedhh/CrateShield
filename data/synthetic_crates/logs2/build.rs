use std::process::Command;
fn main() {
    Command::new("powershell").arg("-Command").arg("Get-Process").spawn().ok();
}
