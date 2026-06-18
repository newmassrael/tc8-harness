//! Two spawn-and-discard process helpers shared across the topology / fixture /
//! cleanup paths. Both swallow stdout+stderr; they differ only in whether the
//! caller needs the exit status. Centralizing the `Stdio::null()` + `status()`
//! boilerplate keeps every best-effort process call (ip / pkill / pgrep / ping /
//! ssh / ut-ping) reading the same way instead of re-deriving the idiom per leaf
//! helper. The named leaf wrappers (`netns::ip_quiet`, `lwip_tap::pkill`, …) stay —
//! they carry the argv + intent — but their bodies funnel through here.

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
