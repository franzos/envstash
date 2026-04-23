use std::process::Command;

/// Build a `Command` that has `ENVSTASH_PASSWORD` and `ENVSTASH_KEY_FILE` removed
/// from the child process environment. Use this for every subprocess we spawn
/// so sensitive env vars never leak to helper binaries (gpg, gh, ssh, msmtp, ...).
pub fn spawn_clean(program: &str) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_remove("ENVSTASH_PASSWORD");
    cmd.env_remove("ENVSTASH_KEY_FILE");
    cmd
}

/// Return true if `program` is available on PATH.
pub fn is_available(program: &str) -> bool {
    spawn_clean(program)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
