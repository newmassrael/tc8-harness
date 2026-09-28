//! A digest of the files this crate is built from.
//!
//! `build.rs` computes it over the tree being compiled and bakes it into the
//! binary; the binary computes it again at startup over the same tree
//! (`main::refuse_a_stale_binary`). Nothing builds the orchestrator for a harness
//! consumer: cmake builds the harness and leaves this binary as it was. After a
//! pin bump the old binary then fails on whatever changed — an unknown site key
//! that reads as a typo in the consumer's own file, or a changed meaning that
//! fails nowhere. Comparing the two digests turns every one of those into a
//! single refusal that says what happened.
//!
//! The one module serves both sides (`build.rs` includes it by path), so the
//! baked value and the startup value cannot be computed two different ways.
//! FNV-1a is enough: this detects an edit, it does not resist an adversary, and
//! it keeps the crate free of a hashing dependency.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Build inputs at the crate root. Everything under `src/` is an input too.
pub const ROOT_INPUTS: &[&str] = &["Cargo.toml", "Cargo.lock", "build.rs"];

/// The build inputs of the crate at `crate_dir`, as paths relative to it, sorted
/// so the digest does not depend on directory iteration order. A root input
/// that does not exist is left out on both sides alike.
pub fn inputs(crate_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = ROOT_INPUTS
        .iter()
        .map(PathBuf::from)
        .filter(|p| crate_dir.join(p).is_file())
        .collect();
    let mut pending = vec![PathBuf::from("src")];
    while let Some(rel) = pending.pop() {
        for entry in fs::read_dir(crate_dir.join(&rel))? {
            let entry = entry?;
            let child = rel.join(entry.file_name());
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(child);
            } else if kind.is_file() {
                out.push(child);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The digest of the crate at `crate_dir`, as 16 hex digits.
pub fn digest(crate_dir: &Path) -> io::Result<String> {
    let mut files = Vec::new();
    for rel in inputs(crate_dir)? {
        let bytes = fs::read(crate_dir.join(&rel))?;
        files.push((rel.to_string_lossy().into_owned(), bytes));
    }
    Ok(digest_of(files.iter().map(|(p, b)| (p.as_str(), b.as_slice()))))
}

/// The digest of `(relative path, contents)` pairs, in the order given. The path
/// and the length are hashed with the contents, so renaming a file, or moving
/// bytes from the end of one file to the start of the next, changes it.
pub fn digest_of<'a>(files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(PRIME);
        }
    };
    for (path, contents) in files {
        feed(path.as_bytes());
        feed(&[0]);
        feed(&(contents.len() as u64).to_le_bytes());
        feed(contents);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_edit_a_rename_or_a_moved_byte_changes_the_digest() {
        let base = digest_of([("a.rs", &b"fn a() {}"[..]), ("b.rs", &b"fn b() {}"[..])]);
        let edited = digest_of([("a.rs", &b"fn a() {1}"[..]), ("b.rs", &b"fn b() {}"[..])]);
        let renamed = digest_of([("c.rs", &b"fn a() {}"[..]), ("b.rs", &b"fn b() {}"[..])]);
        let moved = digest_of([("a.rs", &b"fn a() {}f"[..]), ("b.rs", &b"n b() {}"[..])]);
        assert_eq!(base.len(), 16);
        assert_ne!(base, edited);
        assert_ne!(base, renamed);
        assert_ne!(base, moved);
        assert_eq!(base, digest_of([("a.rs", &b"fn a() {}"[..]), ("b.rs", &b"fn b() {}"[..])]));
    }

    /// Both sides must see the same set; a missed subdirectory would let an edit
    /// there pass unnoticed.
    #[test]
    fn the_inputs_are_the_root_files_and_every_file_under_src() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let inputs = inputs(dir).expect("listing this crate's inputs");
        for root in ["Cargo.toml", "build.rs"] {
            assert!(inputs.contains(&PathBuf::from(root)), "{root} missing from {inputs:?}");
        }
        // Relative to src/, where this file is.
        for under_src in ["main.rs", "topology/dut/probe.rs"] {
            let expected = Path::new("src").join(under_src);
            assert!(inputs.contains(&expected), "{expected:?} missing from {inputs:?}");
        }
        assert!(inputs.iter().all(|p| !p.starts_with("target")), "{inputs:?}");
        assert!(inputs.windows(2).all(|w| w[0] < w[1]), "not sorted: {inputs:?}");
    }
}
