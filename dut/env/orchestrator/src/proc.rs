//! Process helpers shared across the topology / fixture / cleanup paths: two
//! spawn-and-discard runners, and `running_match`, the zombie-free liveness poll.
//! The runners swallow stdout+stderr; they differ only in whether the
//! caller needs the exit status. Centralizing the `Stdio::null()` + `status()`
//! boilerplate keeps every best-effort process call (ip / pkill / pgrep / ping /
//! ssh / ut-ping) reading the same way instead of re-deriving the idiom per leaf
//! helper. The named leaf wrappers (`netns::ip_quiet`, `lwip_tap::pkill`, …) stay —
//! they carry the argv + intent — but their bodies funnel through here.

use std::ffi::OsStr;
use std::fs;
use std::process::{Command, Stdio};

/// Fire-and-forget: run `cmd` with stdout+stderr discarded, ignoring the result —
/// the best-effort `… 2>/dev/null || true` idiom. A failed spawn or non-zero exit
/// is not actionable at these call sites: the operation is already best-effort (a
/// reap of an already-gone process, a teardown of an absent link).
pub(crate) fn run_quiet(cmd: &mut Command) {
    let _ = cmd.stdout(Stdio::null()).stderr(Stdio::null()).status();
}

/// Run `cmd` with stdout+stderr discarded; `true` iff it exited 0. A spawn error
/// counts as `false` — the probed condition (process alive, host reachable, UT
/// answered) is treated as absent when the probe itself could not run.
pub(crate) fn run_ok(cmd: &mut Command) -> bool {
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `pgrep -f PATTERN`, counting only processes that are still RUNNING — the one
/// liveness poll every local kill-and-confirm loop goes through.
///
/// A plain `pgrep` exit status is the wrong answer to "is it still alive?": pgrep
/// lists zombies. A zombie's cmdline is empty, so `-f` falls back to its comm and
/// a pattern that is a process NAME matches the corpse. Measured 2026-09-23: that
/// made the lwip-tap teardown report every cleanly-exited DUT as having ignored
/// SIGTERM (docs/tech-debt.md TD-26). A zombie holds no port and runs no code, so
/// it is not a survivor; it is only an entry its parent has yet to reap. Excluded
/// here, not at each call site, so no poll can count one again. The ssh-remote
/// DUT host applies the same rule with its own remote predicate.
///
/// A spawn error counts as `false`, like `run_ok`.
pub(crate) fn running_match(pattern: &OsStr) -> bool {
    let out = match Command::new("pgrep").arg("-f").arg(pattern).stderr(Stdio::null()).output() {
        Ok(o) => o,
        Err(_) => return false,
    };
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .any(pid_running)
}

/// `/proc/<pid>/stat` names a live, non-zombie process. The state is the first
/// field after the `)` closing the comm (a comm may itself contain `)` or spaces,
/// hence the LAST one). A pid that has vanished since pgrep listed it is not running.
fn pid_running(pid: &str) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    match stat.rfind(')').and_then(|i| stat[i + 1..].trim_start().chars().next()) {
        Some('Z' | 'X' | 'x') => false,
        Some(_) => true,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// The zombie is matched by a plain `pgrep -f <name>` (so this test does exercise
    /// the filter) and is NOT counted as running; the same process alive is.
    #[test]
    fn a_zombie_matching_by_name_is_not_running() {
        let dir = std::env::temp_dir().join(format!("tc8-zombie-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        // Short enough to survive the 15-byte comm truncation whole.
        let name = format!("tc8z{}", std::process::id());
        let link = dir.join(&name);
        let _ = fs::remove_file(&link);
        symlink("/bin/sleep", &link).expect("symlink");

        let mut child = Command::new(&link).arg("30").spawn().expect("spawn");
        let pat = OsStr::new(&name);
        assert!(running_match(pat), "a live process matching the name is running");

        child.kill().expect("kill");
        // Unreaped from here on: poll until the kernel has made it a zombie.
        let pid = child.id().to_string();
        for _ in 0..50 {
            if !pid_running(&pid) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            run_ok(Command::new("pgrep").arg("-f").arg(pat)),
            "precondition: plain pgrep still matches the unreaped zombie"
        );
        assert!(!running_match(pat), "a zombie is not a running process");

        let _ = child.wait();
        let _ = fs::remove_dir_all(&dir);
    }
}
