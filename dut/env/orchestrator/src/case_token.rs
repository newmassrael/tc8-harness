//! The scheduled case token's grammar: `ID` or `suite:ID`.
//!
//! A case's identity is the pair (suite, id) in the harness registry, in its spec
//! inventory and in every override axis the inventory carries (case_suite.h and
//! spec_inventory.h). The harness prints the in-tree suite's ids bare and any other
//! suite's qualified, and `dut/env/list-cases-ids.awk` passes both through as
//! first-class tokens. This module is the orchestrator's one reading of that
//! grammar, so every table it keys on a token resolves the same pair.

/// The in-tree suite's name. Its single source of truth is `kDefaultSuite` in
/// `src/sce_integration/include/sce_integration/case_suite.h`; the test below pins
/// this copy to it, the way `src/harness/CMakeLists.txt` derives its own.
pub const DEFAULT_SUITE: &str = "tc8";

/// Split a token into its suite qualifier (None when bare) and its id.
pub fn split(token: &str) -> (Option<&str>, &str) {
    match token.split_once(':') {
        Some((suite, id)) => (Some(suite), id),
        None => (None, token),
    }
}

/// Suite names compare ASCII case-insensitively at every layer.
pub fn is_default_suite(suite: &str) -> bool {
    suite.eq_ignore_ascii_case(DEFAULT_SUITE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn default_suite_matches_the_cpp_ssot() {
        let header = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../src/sce_integration/include/sce_integration/case_suite.h");
        let text = std::fs::read_to_string(&header).expect("read case_suite.h");
        let line = text
            .lines()
            .find(|l| l.contains("constexpr") && l.contains("kDefaultSuite ="))
            .expect("case_suite.h defines kDefaultSuite = \"...\"");
        let value = line.split('"').nth(1).expect("quoted suite name");
        assert_eq!(value, DEFAULT_SUITE, "case_token::DEFAULT_SUITE drifted from kDefaultSuite");
    }

    #[test]
    fn splits_bare_and_qualified_tokens() {
        assert_eq!(split("ARP_03"), (None, "ARP_03"));
        assert_eq!(split("demo:ARP_03"), (Some("demo"), "ARP_03"));
        assert!(is_default_suite("TC8"));
        assert!(!is_default_suite("demo"));
    }
}
