//! A run's schedulable unit: which case the harness runs, and which of the case's
//! authored negative rows the run drives.
//!
//! The two are different identities, and keeping them as one string is the defect
//! this type exists to prevent. The harness knows a case by its id alone; a run
//! schedules, reports and stores ARTIFACTS per unit. A case authoring two negative
//! rows is two units of one case. When the row index was carried inside a string
//! (`ARP_35#1`) and split off before dispatch, the bare case id named every file
//! the run wrote, so a case's two rows running on two workers shared one harness
//! log, one DUT log, one pcap and one start-order handshake, and each row read back
//! whichever verdict landed last (docs/tech-debt.md TD-68).
//!
//! So a unit is a value with both parts, and the only things derived from the
//! RENDERED unit are the ones that must be unique per run: the schedule key, the
//! report name and the artifact names.

use std::collections::HashMap;
use std::fmt;

use anyhow::{bail, Result};

/// One schedulable unit. Row 0 is the case itself, or its primary negative row; a
/// row above 0 exists only for a case authoring extra negative rows.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UnitId {
    case: String,
    row: u32,
}

impl UnitId {
    /// The case itself: a positive run, a known-fail assertion, or a primary
    /// negative row.
    pub fn case(case: impl Into<String>) -> Self {
        Self { case: case.into(), row: 0 }
    }

    /// One of a case's authored negative rows, by the index `--list-neg-rows`
    /// printed and `--negative-row-index` takes.
    pub fn negative_row(case: impl Into<String>, row: u32) -> Self {
        Self { case: case.into(), row }
    }

    /// The case token the harness runs (`--case`), and every per-case table keys on.
    pub fn case_id(&self) -> &str {
        &self.case
    }

    /// The authored negative row this unit drives; 0 for the primary.
    pub fn row(&self) -> u32 {
        self.row
    }
}

/// The unit's run-unique name: the bare case for row 0, `CASE#N` for an extra row.
/// Row 0 keeps the bare id so every report line and artifact name of a case with
/// one row is what it has always been.
impl fmt::Display for UnitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.row == 0 {
            f.write_str(&self.case)
        } else {
            write!(f, "{}#{}", self.case, self.row)
        }
    }
}

/// Refuse a schedule that holds one unit twice.
///
/// A unit's artifacts are named from the unit, so two copies of one unit would
/// write the same files, and the verdict read back from the harness log would be
/// whichever copy finished last. The comparison is ASCII case-insensitive because
/// the harness resolves case tokens that way: `arp_33` and `ARP_33` are one case.
pub fn refuse_duplicates(units: &[UnitId]) -> Result<()> {
    let mut seen: HashMap<(String, u32), &UnitId> = HashMap::new();
    for unit in units {
        if let Some(first) = seen.insert((unit.case.to_ascii_uppercase(), unit.row), unit) {
            bail!(
                "the schedule holds {first} and {unit}, which are the same unit: each run's \
                 logs, pcap and verdict are named from its unit, so the two would overwrite \
                 each other. Name each case once; to repeat a case, run the orchestrator again"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_zero_renders_as_the_bare_case_and_an_extra_row_carries_its_index() {
        assert_eq!(UnitId::case("ARP_35").to_string(), "ARP_35");
        assert_eq!(UnitId::negative_row("ARP_35", 0).to_string(), "ARP_35");
        let extra = UnitId::negative_row("ARP_35", 1);
        assert_eq!(extra.to_string(), "ARP_35#1");
        // The harness still gets the bare case: the index travels separately.
        assert_eq!(extra.case_id(), "ARP_35");
        assert_eq!(extra.row(), 1);
    }

    #[test]
    fn units_order_by_case_then_row() {
        let mut units =
            [UnitId::case("ARP_34"), UnitId::negative_row("ARP_33", 1), UnitId::case("ARP_33")];
        units.sort();
        let names: Vec<String> = units.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["ARP_33", "ARP_33#1", "ARP_34"]);
    }

    /// The two rows of one case are DIFFERENT units, which is the property the
    /// artifact naming depends on, so they must pass where a repeat must not.
    #[test]
    fn two_rows_of_one_case_are_distinct_but_a_repeated_unit_is_refused() {
        let rows = [UnitId::case("ARP_35"), UnitId::negative_row("ARP_35", 1)];
        assert!(refuse_duplicates(&rows).is_ok());

        let repeat = [UnitId::case("ARP_33"), UnitId::case("ARP_34"), UnitId::case("ARP_33")];
        let err = refuse_duplicates(&repeat).expect_err("a repeated unit is refused").to_string();
        assert!(err.contains("ARP_33"), "the refusal names the unit: {err}");

        let spelled_twice = [UnitId::case("arp_33"), UnitId::case("ARP_33")];
        assert!(refuse_duplicates(&spelled_twice).is_err(), "case-insensitive, like the harness");
    }
}
