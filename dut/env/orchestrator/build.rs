//! Bakes the digest of this crate's sources, and the commit they were built at,
//! into the binary. The binary checks the digest against its source tree at
//! startup (src/source_digest.rs says why).

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "src/source_digest.rs"]
mod source_digest;

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    for input in source_digest::ROOT_INPUTS {
        println!("cargo:rerun-if-changed={input}");
    }
    // A directory is scanned recursively for changes.
    println!("cargo:rerun-if-changed=src");
    let digest = source_digest::digest(&dir).expect("digesting the orchestrator's sources");
    println!("cargo:rustc-env=TC8_ORCH_SOURCE_DIGEST={digest}");
    println!("cargo:rustc-env=TC8_ORCH_BUILD_COMMIT={}", build_commit(&dir));
}

/// The commit the sources were built at, marked `-dirty` when the crate has
/// uncommitted changes, or `unknown` outside a git checkout.
fn build_commit(dir: &Path) -> String {
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    match git(&["rev-parse", "--short=12", "HEAD"]) {
        Some(head) => match git(&["status", "--porcelain", "--", "."]) {
            Some(changes) if !changes.is_empty() => format!("{head}-dirty"),
            _ => head,
        },
        None => "unknown".to_string(),
    }
}
