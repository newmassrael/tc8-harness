//! JUnit (Surefire-shape) reporter — the `--junit-xml` output, ported from
//! smoke-test.sh's awk aggregator so both drivers emit the SAME schema (consumed
//! by GitHub Actions dorny/test-reporter). One `<testcase>` per case, grouped into
//! a `<testsuite>` by category prefix; `render` is pure over the records + run
//! timestamp so it is unit-tested without a run.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

/// One case's outcome for the report — the pass/fail/skip trichotomy bash's
/// aggregator renders (a non-conclusion is a skip carrying its `inconclusive:`
/// reason, exactly as bash routes it).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

/// One `<testcase>`. `name` is already `_neg`-suffixed for a negative run (bash
/// `junit_record_case` names negatives `<case>_neg`); `negative` drives the
/// `<failure type=...>` attribute (bash's `mode`). `message` is the reason for a
/// fail/skip, empty for a pass.
#[derive(Clone)]
pub struct CaseRecord {
    pub name: String,
    pub status: Status,
    pub duration_s: f64,
    pub message: String,
    pub negative: bool,
}

/// The testsuite a case rolls up into: its id with the `_neg`/`_NEG` /
/// `_PLATFORM_KNOWN_FAIL` / trailing `_<digits>` suffix stripped — bash's
/// `suite_of` (smoke-test.sh awk). `SOMEIPSRV_FORMAT_14` -> `SOMEIPSRV_FORMAT`,
/// `ARP_03_neg` -> `ARP`.
pub fn suite_of(name: &str) -> String {
    let mut s = name;
    for suffix in ["_neg", "_NEG", "_PLATFORM_KNOWN_FAIL"] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped;
            break;
        }
    }
    // Strip one trailing `_<digits>` group (the case number).
    if let Some(idx) = s.rfind('_') {
        if !s[idx + 1..].is_empty() && s[idx + 1..].bytes().all(|b| b.is_ascii_digit()) {
            s = &s[..idx];
        }
    }
    s.to_string()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Render the Surefire XML. Pure: suites and cases are emitted in sorted order
/// (deterministic + diffable; the consumer is order-insensitive), tallies are
/// derived, and every text value is XML-escaped. `timestamp` is the run's
/// `date -u +%Y-%m-%dT%H:%M:%S` (supplied by the caller so this stays pure).
pub fn render(records: &[CaseRecord], timestamp: &str) -> String {
    // Group into suites (BTreeMap = sorted by name), preserving per-suite records.
    let mut suites: BTreeMap<String, Vec<&CaseRecord>> = BTreeMap::new();
    for r in records {
        suites.entry(suite_of(&r.name)).or_default().push(r);
    }

    let total = records.len();
    let total_fail = records.iter().filter(|r| r.status == Status::Fail).count();
    let total_skip = records.iter().filter(|r| r.status == Status::Skip).count();
    let total_time: f64 = records.iter().map(|r| r.duration_s).sum();

    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<testsuites name=\"tc8-harness smoke\" tests=\"{total}\" failures=\"{total_fail}\" \
         skipped=\"{total_skip}\" time=\"{total_time:.3}\" timestamp=\"{}\">\n",
        xml_escape(timestamp)
    ));
    for (suite, mut cases) in suites {
        cases.sort_by(|a, b| a.name.cmp(&b.name));
        let s_fail = cases.iter().filter(|r| r.status == Status::Fail).count();
        let s_skip = cases.iter().filter(|r| r.status == Status::Skip).count();
        let s_time: f64 = cases.iter().map(|r| r.duration_s).sum();
        let esc_suite = xml_escape(&suite);
        out.push_str(&format!(
            "  <testsuite name=\"{esc_suite}\" tests=\"{}\" failures=\"{s_fail}\" \
             skipped=\"{s_skip}\" time=\"{s_time:.3}\">\n",
            cases.len()
        ));
        for r in cases {
            let open = format!(
                "    <testcase classname=\"{esc_suite}\" name=\"{}\" time=\"{:.3}\"",
                xml_escape(&r.name),
                r.duration_s
            );
            match r.status {
                Status::Pass => out.push_str(&format!("{open}/>\n")),
                Status::Fail => {
                    let msg = if r.message.is_empty() {
                        "no verdict line".to_string()
                    } else {
                        r.message.clone()
                    };
                    let ty = if r.negative { "negative" } else { "positive" };
                    out.push_str(&format!(
                        "{open}><failure type=\"{ty}\" message=\"{}\"/></testcase>\n",
                        xml_escape(&msg)
                    ));
                }
                Status::Skip => out.push_str(&format!(
                    "{open}><skipped message=\"{}\"/></testcase>\n",
                    xml_escape(&r.message)
                )),
            }
        }
        out.push_str("  </testsuite>\n");
    }
    out.push_str("</testsuites>\n");
    out
}

/// Render and write the report to `path`, creating parent dirs (bash `mkdir -p`).
pub fn write(path: &Path, records: &[CaseRecord], timestamp: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating --junit-xml parent dir {}", parent.display()))?;
    }
    std::fs::write(path, render(records, timestamp))
        .with_context(|| format!("writing --junit-xml {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_of_strips_number_and_neg_suffixes() {
        assert_eq!(suite_of("SOMEIPSRV_FORMAT_14"), "SOMEIPSRV_FORMAT");
        assert_eq!(suite_of("ARP_03_neg"), "ARP");
        assert_eq!(suite_of("ARP_28_NEG"), "ARP");
        assert_eq!(suite_of("IPv4_HEADER_05_PLATFORM_KNOWN_FAIL"), "IPv4_HEADER");
        assert_eq!(suite_of("ARP_03"), "ARP");
    }

    #[test]
    fn render_matches_surefire_shape() {
        let recs = vec![
            CaseRecord {
                name: "ARP_03".into(),
                status: Status::Pass,
                duration_s: 7.409,
                message: String::new(),
                negative: false,
            },
            CaseRecord {
                name: "ARP_13_neg".into(),
                status: Status::Fail,
                duration_s: 4.698,
                message: "expected 'fail:x', harness returned 'pass'".into(),
                negative: true,
            },
            CaseRecord {
                name: "SOMEIP_ETS_035_neg".into(),
                status: Status::Skip,
                duration_s: 1.5,
                message: "guard not exercised: inconclusive:no_method_response".into(),
                negative: true,
            },
        ];
        let xml = render(&recs, "2026-07-18T00:00:00");
        // Header tallies: 3 tests, 1 failure, 1 skip.
        assert!(xml.contains(
            "<testsuites name=\"tc8-harness smoke\" tests=\"3\" failures=\"1\" skipped=\"1\""
        ));
        // Two suites, sorted: ARP before SOMEIP_ETS.
        let arp = xml.find("name=\"ARP\"").expect("ARP suite");
        let ets = xml.find("name=\"SOMEIP_ETS\"").expect("ETS suite");
        assert!(arp < ets, "suites must be sorted");
        // Pass = self-closing; fail carries type+message; skip carries message.
        assert!(xml.contains("name=\"ARP_03\" time=\"7.409\"/>"));
        assert!(xml.contains("<failure type=\"negative\" message=\"expected &#x27;fail:x&#x27;")
            || xml.contains("<failure type=\"negative\" message=\"expected 'fail:x'"));
        assert!(xml.contains("<skipped message=\"guard not exercised: inconclusive:no_method_response\"/>"));
    }

    #[test]
    fn render_escapes_xml_metacharacters() {
        let recs = vec![CaseRecord {
            name: "X_01".into(),
            status: Status::Fail,
            duration_s: 0.0,
            message: "a<b>&\"c".into(),
            negative: false,
        }];
        let xml = render(&recs, "T");
        assert!(xml.contains("a&lt;b&gt;&amp;&quot;c"));
        assert!(!xml.contains("a<b>"));
    }
}
