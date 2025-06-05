use std::io;
use std::os::windows::process::CommandExt;
use std::process::{Command, Output};

use encoding_rs::GBK;
use windows::Win32::System::Threading::CREATE_NO_WINDOW;

pub fn set_interface_name(old_name: &str, new_name: &str) -> io::Result<()> {
    let cmd = format!(
        " netsh interface set interface name={:?} newname={:?}",
        old_name, new_name
    );
    exe_cmd(&cmd)
}
pub fn exe_cmd(cmd: &str) -> io::Result<()> {
    let out = Command::new("cmd")
        .creation_flags(CREATE_NO_WINDOW.0)
        .arg("/C")
        .arg(cmd)
        .output()?;
    output(cmd, out)
}
fn gbk_to_utf8(bytes: &[u8]) -> String {
    let (msg, _, _) = GBK.decode(bytes);
    msg.to_string()
}
fn output(cmd: &str, out: Output) -> io::Result<()> {
    if !out.status.success() {
        let msg = if !out.stderr.is_empty() {
            match std::str::from_utf8(&out.stderr) {
                Ok(msg) => msg.to_string(),
                Err(_) => gbk_to_utf8(&out.stderr),
            }
        } else if !out.stdout.is_empty() {
            match std::str::from_utf8(&out.stdout) {
                Ok(msg) => msg.to_string(),
                Err(_) => gbk_to_utf8(&out.stdout),
            }
        } else {
            String::new()
        };
        return Err(io::Error::other(format!(
            "cmd=\"{}\",out=\"{}\"",
            cmd,
            msg.trim()
        )));
    }
    Ok(())
}
