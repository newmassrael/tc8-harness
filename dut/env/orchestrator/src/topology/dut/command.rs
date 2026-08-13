//! `command` DUT lifecycle — a DUT the site launches by an argv it supplies, for a
//! deployment where the DUT is not an executable on this filesystem at all: a sibling
//! container, a device that only has to be TOLD to start, a lab rig behind a script.
//!
//! The orchestrator still owns the lifecycle. It renders the operator's argv, runs it
//! INSIDE the namespace the tester transport prepared, hands it the same vsomeip
//! environment the reference DUT gets, and captures its output into the per-case DUT
//! log — so a postmortem reads the same whether the DUT was ours or theirs. What the
//! site supplies is which command, not whether any of that happens.
//!
//! The reap is an operator-supplied `stop` argv rather than the argv[0] marker every
//! other local lifecycle uses. That is forced, not a preference: the start argv
//! belongs to the operator, so a `pkill -f` on it could match anything on the host,
//! and killing a local wrapper would not stop a DUT that lives in a container anyway.
//! `stop` is therefore required at config resolve time (see `site::DutSpec`).

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::{Child, Command as StdCommand, Stdio};

use super::{DutLifecycle, DutPlacement};
use crate::config::Config;

/// A site-supplied launcher and its matching stop command.
pub(crate) struct CommandDut<'a> {
    cfg: &'a Config,
    start: Vec<String>,
    stop: Vec<String>,
    max_workers: u32,
}

impl<'a> CommandDut<'a> {
    pub(crate) fn new(cfg: &'a Config, start: Vec<String>, stop: Vec<String>, max_workers: u32) -> Self {
        CommandDut { cfg, start, stop, max_workers }
    }

    /// The value of one per-case placeholder. `None` for a name this renderer does
    /// not know — which, given `placeholder_set_is_fully_rendered` below, can only
    /// mean a name that is not a placeholder at all.
    fn placeholder_value(&self, name: &str, w: u32, ns: &str, dlog: &Path, cfg_path: &Path) -> Option<String> {
        let base = self.cfg.vsomeip_base.join(w.to_string());
        match name {
            "WORKER" => Some(w.to_string()),
            "DUT_NETNS" => Some(ns.to_string()),
            "DUT_LOG" => Some(dlog.display().to_string()),
            "VSOMEIP_CONFIG" => Some(cfg_path.display().to_string()),
            "COMMONAPI_CONFIG" => Some(self.cfg.capi_cfg.display().to_string()),
            "VSOMEIP_BASE_PATH" => Some(format!("{}/", base.display())),
            _ => None,
        }
    }

    /// Substitute the per-case placeholders in one argv element. Deliberately a plain
    /// textual substitution over a CLOSED set of names: the argv is executed directly
    /// (no shell), so a substituted value can never be re-split into extra arguments
    /// or reinterpreted as a redirection. A `${...}` this renderer does not know is
    /// left verbatim rather than silently emptied — config load already rejected any
    /// genuinely unset environment variable, so reaching here means the operator
    /// wrote a literal the DUT launcher is expected to see.
    fn render(&self, arg: &str, w: u32, ns: &str, dlog: &Path, cfg_path: &Path) -> String {
        let mut out = String::with_capacity(arg.len());
        let mut rest = arg;
        while let Some(start) = rest.find("${") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let end = match after.find('}') {
                Some(e) => e,
                None => break, // unterminated — copy the remainder verbatim below
            };
            let name = &after[..end];
            match self.placeholder_value(name, w, ns, dlog, cfg_path) {
                Some(v) => out.push_str(&v),
                None => {
                    out.push_str("${");
                    out.push_str(name);
                    out.push('}');
                }
            }
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        out
    }

    fn render_all(&self, argv: &[String], w: u32, ns: &str, dlog: &Path, cfg_path: &Path) -> Vec<String> {
        argv.iter().map(|a| self.render(a, w, ns, dlog, cfg_path)).collect()
    }
}

impl DutLifecycle for CommandDut<'_> {
    fn name(&self) -> &'static str {
        "command"
    }

    fn max_workers(&self) -> Option<u32> {
        Some(self.max_workers)
    }

    fn spawns_per_case(&self) -> bool {
        true
    }

    fn supports_negative(&self) -> bool {
        // The curated negative rows assert deliberately WRONG expectations to prove
        // the harness's own verdict machinery still fails them. That only means
        // something against our reference implementation: against a DUT we did not
        // build, a negative row that "passes" may simply be a DUT that differs, and
        // the run would report self-validation it never performed.
        false
    }

    fn start_dut(
        &self,
        w: u32,
        placement: &DutPlacement,
        dlog: &Path,
        cfg_path: &Path,
        extra_env: &[String],
    ) -> Result<Option<Child>> {
        let ns = placement.require_netns(self.name())?;
        let argv = self.render_all(&self.start, w, ns, dlog, cfg_path);
        let log = fs::File::create(dlog).context("creating dut log")?;
        let err = log.try_clone()?;
        let base = self.cfg.vsomeip_base.join(w.to_string());

        // `ip netns exec <ns> <argv...>` — the DUT lands on the transport's wire, and
        // on a kernel stack we own, exactly like the reference DUT does.
        let mut cmd = StdCommand::new("ip");
        cmd.args(["netns", "exec", ns]);
        cmd.args(&argv);
        // The same environment contract the reference DUT is given. Set as real env
        // vars rather than an `env KEY=VAL` argv prefix so a launcher that is a script
        // or a container client inherits them without having to parse anything.
        cmd.env("COMMONAPI_CONFIG", &self.cfg.capi_cfg)
            .env("VSOMEIP_CONFIGURATION", cfg_path)
            .env("VSOMEIP_APPLICATION_NAME", "tc8-dut")
            .env("VSOMEIP_BASE_PATH", format!("{}/", base.display()));
        // Per-case DUT flavor env (CASE_VSOMEIP_VARIANT). A launcher that fronts a
        // foreign DUT may well ignore these; passing them anyway keeps the contract
        // identical to the reference lifecycle's, so a launcher CAN honour them.
        for kv in extra_env {
            if let Some((k, v)) = kv.split_once('=') {
                cmd.env(k, v);
            }
        }
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(err))
            .spawn()
            .with_context(|| format!("spawning site DUT launcher {:?} via ip netns exec", argv))?;
        Ok(Some(child))
    }

    fn stop_dut(&self, w: u32, placement: &DutPlacement) -> Result<()> {
        // The stop argv gets the same placeholders as start, so it can address the
        // same worker-scoped container/device. Rendered against the worker's default
        // vsomeip config: the per-case flavor is a start-time concern, and a stop
        // command that needed to know the flavor could not reap a crashed start.
        let ns = placement.netns().unwrap_or_default();
        let dlog = Path::new("");
        let argv = self.render_all(&self.stop, w, ns, dlog, &self.cfg.vsomeip_cfg);
        let (prog, rest) = match argv.split_first() {
            Some(x) => x,
            None => return Ok(()), // resolve rejects an empty stop; nothing to run
        };
        // Best-effort and LOUD: the run continues (the dispatcher's bounded wait is
        // the backstop), but a stop that failed means a DUT may survive into the next
        // case, which is exactly the kind of silent carry-over that produces a
        // mystery failure two cases later.
        let mut c = StdCommand::new(prog);
        c.args(rest).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        match c.status() {
            Ok(st) if st.success() => Ok(()),
            Ok(st) => {
                eprintln!(
                    "orchestrator: warning: worker {w} DUT stop command {argv:?} exited {st}; a surviving DUT can affect the next case"
                );
                Ok(())
            }
            Err(e) => {
                eprintln!(
                    "orchestrator: warning: worker {w} could not run the DUT stop command {argv:?}: {e}"
                );
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::fake_cfg;
    use crate::site::DUT_ARGV_PLACEHOLDERS;

    fn dut(cfg: &Config) -> CommandDut<'_> {
        CommandDut::new(cfg, vec!["/launch".into()], vec!["/stop".into()], 1)
    }

    #[test]
    fn placeholder_set_is_fully_rendered() {
        // The drift guard between the two halves of the placeholder contract: config
        // load PRESERVES exactly DUT_ARGV_PLACEHOLDERS, so this renderer must give
        // every one of them a value. A name preserved at load but unknown here would
        // reach the DUT launcher as a literal `${NAME}` — a silent mis-launch.
        let cfg = fake_cfg();
        let d = dut(&cfg);
        for name in DUT_ARGV_PLACEHOLDERS {
            assert!(
                d.placeholder_value(name, 0, "tc8-dut-0", Path::new("/l"), Path::new("/c")).is_some(),
                "placeholder ${{{name}}} is preserved at config load but has no value here"
            );
        }
    }

    #[test]
    fn start_against_a_placementless_transport_names_the_mismatch() {
        // Pairing this lifecycle with a transport that owns no namespace is a
        // construction bug. It must say so rather than start a DUT on the wrong stack,
        // and it must decide that BEFORE touching the log file.
        let cfg = fake_cfg();
        let err = dut(&cfg)
            .start_dut(0, &DutPlacement::Foreign, Path::new("/x.log"), Path::new("/c"), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("command"), "{err}");
        assert!(err.contains("namespace"), "{err}");
    }

    #[test]
    fn stop_failure_is_surfaced_but_never_aborts_the_run() {
        // Both failure shapes return Ok: the run continues (the dispatcher's bounded
        // wait is the backstop) while the warning tells the operator a DUT may have
        // survived into the next case. An Err here would abort a worker from the
        // teardown path, turning one leaked DUT into a lost run.
        let cfg = fake_cfg();
        let ns = DutPlacement::Netns("tc8-dut-0".into());
        // (a) the stop command cannot be spawned at all
        let unspawnable =
            CommandDut::new(&cfg, vec!["/nx/start".into()], vec!["/nx/stop".into()], 1);
        assert!(unspawnable.stop_dut(0, &ns).is_ok());
        // (b) it runs and exits non-zero
        let failing =
            CommandDut::new(&cfg, vec!["/bin/true".into()], vec!["/bin/false".into()], 1);
        assert!(failing.stop_dut(0, &ns).is_ok());
        // (c) and it stays non-fatal even with no namespace to address
        assert!(failing.stop_dut(0, &DutPlacement::Foreign).is_ok());
    }

    #[test]
    fn renders_known_placeholders_and_leaves_unknown_verbatim() {
        let cfg = fake_cfg();
        let d = dut(&cfg);
        let r = |s: &str| d.render(s, 3, "tc8-dut-3", Path::new("/logs/a.log"), Path::new("/cfg/v.json"));
        assert_eq!(r("--worker=${WORKER}"), "--worker=3");
        assert_eq!(r("--ns=${DUT_NETNS}"), "--ns=tc8-dut-3");
        assert_eq!(r("${VSOMEIP_CONFIG}"), "/cfg/v.json");
        assert_eq!(r("${DUT_LOG}"), "/logs/a.log");
        // Not a placeholder: passed through so the launcher sees what was written.
        assert_eq!(r("${NOT_A_PLACEHOLDER}"), "${NOT_A_PLACEHOLDER}");
        // Unterminated brace: copied verbatim, never truncated.
        assert_eq!(r("${OPEN"), "${OPEN");
        // A value is substituted into ONE argv element; it can never split into two.
        assert_eq!(r("x${WORKER}y"), "x3y");
    }
}
