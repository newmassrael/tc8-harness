// verdict_migrate — one-time migration of SCXML <final> verdicts to the
// docs/verdict_policy.md role model (semantics A).
//
// It does NOT invent verdicts. For every non-pass <final> it reads the kind of
// transition that REACHES that final and applies the codified policy:
//   * reached only by a timer/deadline transition (no cond) -> non-conclusion
//       -> inconclusive  (precondition_unmet if the deadline fires in the
//        initial state, else property_unobserved)
//   * reached by a cond transition (an observed bad frame)  -> observed_violation
//       -> fail (class unchanged, role added)
//   * already carries a "role"                              -> skip (idempotent)
//   * pass                                                  -> skip (role optional)
//   * anything it cannot map confidently                    -> UNCLASSIFIED, skipped
//
// EVERY final and EVERY branch is logged. There are no silent skips: a final
// the tool will not touch is announced with its reason. --apply performs only
// count-checked replacements; an unexpected match count is logged and skipped.
//
// Usage:  verdict_migrate [--apply] [ROOT ...]      (default ROOT: tests)

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const R_PRECOND: &str = "precondition_unmet"; // -> inconclusive
const R_PROPERTY: &str = "property_unobserved"; // -> inconclusive
const R_VIOLATION: &str = "observed_violation"; // -> fail

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Deadline, // timer-driven, no cond
    Cond,     // has a cond predicate (an observed frame matched)
    Plain,    // event-driven, no cond, not a timer (e.g. a raw phase advance)
}

struct Transition {
    target: String,
    kind: Kind,
    from_state: String,
}

struct Final {
    id: String,
    verdict: String,
    role: String,
    content: String, // the exact JSON object text inside <content>...</content>
}

struct Stats {
    reclassified: usize,
    violation_tagged: usize,
    already: usize,
    pass: usize,
    unclassified: usize,
    edits: usize,
}

fn main() {
    let mut apply = false;
    let mut roots: Vec<String> = Vec::new();
    for a in env::args().skip(1) {
        match a.as_str() {
            "--apply" => apply = true,
            "--plan" => apply = false,
            _ => roots.push(a),
        }
    }
    if roots.is_empty() {
        roots.push("tests".to_string());
    }
    println!("== verdict_migrate ({}) ==", if apply { "APPLY" } else { "PLAN" });

    let mut files: Vec<PathBuf> = Vec::new();
    for r in &roots {
        collect(Path::new(r), &mut files);
    }
    files.sort();
    println!("scanning {} SCXML/template files under {:?}\n", files.len(), roots);

    let mut total = Stats {
        reclassified: 0,
        violation_tagged: 0,
        already: 0,
        pass: 0,
        unclassified: 0,
        edits: 0,
    };
    let mut unclassified_list: Vec<String> = Vec::new();

    for f in &files {
        process(f, apply, &mut total, &mut unclassified_list);
    }

    println!("\n== summary ==");
    println!("  reclassified fail->inconclusive : {}", total.reclassified);
    println!("  observed_violation tagged (fail): {}", total.violation_tagged);
    println!("  already roled (skipped)         : {}", total.already);
    println!("  pass (skipped)                  : {}", total.pass);
    println!("  UNCLASSIFIED (skipped, manual)  : {}", total.unclassified);
    if apply {
        println!("  string replacements applied     : {}", total.edits);
    }
    if !unclassified_list.is_empty() {
        println!("\n== UNCLASSIFIED finals (handle by hand) ==");
        for u in &unclassified_list {
            println!("  {}", u);
        }
    }
}

fn collect(p: &Path, out: &mut Vec<PathBuf>) {
    if p.is_dir() {
        if let Ok(rd) = fs::read_dir(p) {
            for e in rd.flatten() {
                collect(&e.path(), out);
            }
        }
    } else if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
        if name.ends_with(".scxml") || name.ends_with(".sce-template.xml") {
            out.push(p.to_path_buf());
        }
    }
}

fn process(path: &Path, apply: bool, total: &mut Stats, unclassified: &mut Vec<String>) {
    let fname = path.display().to_string();
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            println!("[{}] READ ERROR: {} -> SKIP", fname, e);
            return;
        }
    };

    let timers = collect_timer_events(&text);
    let initial = initial_state(&text);
    let transitions = collect_transitions(&text, &timers);
    let finals = collect_finals(&text);

    // index inbound transitions by target id
    let mut inbound: BTreeMap<String, Vec<&Transition>> = BTreeMap::new();
    for t in &transitions {
        inbound.entry(t.target.clone()).or_default().push(t);
    }

    let mut planned: Vec<(String, String, String, String)> = Vec::new();
    // (old_id, new_id, old_content, new_content)

    for f in &finals {
        let tag = format!("[{}] final '{}'", fname, f.id);
        if f.verdict == "pass" {
            println!("{}: verdict=pass -> skip (role optional)", tag);
            total.pass += 1;
            continue;
        }
        if !f.role.is_empty() {
            println!("{}: already roled ({}) -> skip (idempotent)", tag, f.role);
            total.already += 1;
            continue;
        }
        let ins = match inbound.get(&f.id) {
            Some(v) => v,
            None => {
                println!("{}: UNCLASSIFIED no inbound transition found -> SKIP", tag);
                total.unclassified += 1;
                unclassified.push(format!("{} (no inbound)", tag));
                continue;
            }
        };
        let has_cond = ins.iter().any(|t| t.kind == Kind::Cond);
        let has_deadline = ins.iter().any(|t| t.kind == Kind::Deadline);
        let has_plain = ins.iter().any(|t| t.kind == Kind::Plain);
        let states: Vec<&str> = ins.iter().map(|t| t.from_state.as_str()).collect();

        // Decision tree — every branch logs.
        if has_plain {
            println!(
                "{}: UNCLASSIFIED inbound has PLAIN (event w/o cond) from {:?} -> SKIP",
                tag, states
            );
            total.unclassified += 1;
            unclassified.push(format!("{} (plain inbound)", tag));
            continue;
        }
        if has_cond && has_deadline {
            println!(
                "{}: UNCLASSIFIED inbound mixes COND+DEADLINE from {:?} -> SKIP",
                tag, states
            );
            total.unclassified += 1;
            unclassified.push(format!("{} (mixed inbound)", tag));
            continue;
        }
        if has_cond {
            // observed bad frame -> fail / observed_violation
            if f.verdict != "fail" {
                println!(
                    "{}: UNCLASSIFIED inbound=COND but verdict={} (expected fail) -> SKIP",
                    tag, f.verdict
                );
                total.unclassified += 1;
                unclassified.push(format!("{} (cond but verdict={})", tag, f.verdict));
                continue;
            }
            let new_content = with_role(&f.content, "fail", R_VIOLATION);
            println!(
                "{}: inbound=COND verdict=fail from {:?} -> observed_violation (fail kept) +role",
                tag, states
            );
            planned.push((f.id.clone(), f.id.clone(), f.content.clone(), new_content));
            total.violation_tagged += 1;
            continue;
        }
        if has_deadline {
            let from_initial = ins
                .iter()
                .any(|t| t.kind == Kind::Deadline && t.from_state == initial);
            let role = if from_initial { R_PRECOND } else { R_PROPERTY };
            // class: fail -> inconclusive; an existing inconclusive just gets a role.
            if f.verdict == "fail" {
                let new_content = with_role(
                    &set_verdict(&f.content, "inconclusive"),
                    "inconclusive",
                    role,
                );
                let new_id = rename_fail(&f.id);
                println!(
                    "{}: inbound=DEADLINE verdict=fail from {:?} initial='{}' -> inconclusive ({}) id->'{}'",
                    tag, states, initial, role, new_id
                );
                planned.push((f.id.clone(), new_id, f.content.clone(), new_content));
                total.reclassified += 1;
                continue;
            } else if f.verdict == "inconclusive" {
                let new_content = with_role(&f.content, "inconclusive", role);
                println!(
                    "{}: inbound=DEADLINE verdict=inconclusive from {:?} -> +role ({})",
                    tag, states, role
                );
                planned.push((f.id.clone(), f.id.clone(), f.content.clone(), new_content));
                total.reclassified += 1;
                continue;
            } else {
                println!(
                    "{}: UNCLASSIFIED inbound=DEADLINE verdict={} -> SKIP",
                    tag, f.verdict
                );
                total.unclassified += 1;
                unclassified.push(format!("{} (deadline verdict={})", tag, f.verdict));
                continue;
            }
        }
        // no inbound kind matched (empty ins?) — shouldn't reach
        println!("{}: UNCLASSIFIED no usable inbound kind -> SKIP", tag);
        total.unclassified += 1;
        unclassified.push(format!("{} (no kind)", tag));
    }

    if !apply || planned.is_empty() {
        return;
    }

    // Apply: count-checked replacements. Content first (id-independent), then
    // whole-token id rename (covers id=, target=, and comment mentions).
    let mut buf = text;
    for (old_id, new_id, old_content, new_content) in &planned {
        if old_content != new_content {
            let n = buf.matches(old_content.as_str()).count();
            if n != 1 {
                println!(
                    "[{}] APPLY-SKIP content for '{}' matched {} times (expected 1)",
                    fname, old_id, n
                );
                continue;
            }
            buf = buf.replace(old_content.as_str(), new_content);
            total.edits += 1;
            println!("[{}] APPLY content '{}' updated", fname, old_id);
        }
        if old_id != new_id {
            if old_id.contains("{$") {
                println!("[{}] APPLY-SKIP id rename '{}' (templated id)", fname, old_id);
                continue;
            }
            let (nb, cnt) = replace_token(&buf, old_id, new_id);
            buf = nb;
            total.edits += cnt;
            println!(
                "[{}] APPLY id '{}' -> '{}' ({} token occurrences: id=/target=/comments)",
                fname, old_id, new_id, cnt
            );
        }
    }
    // Residual-reference guard: announce any leftover mention of a renamed id.
    for (old_id, new_id, _, _) in &planned {
        if old_id != new_id && !old_id.contains("{$") && buf.contains(old_id.as_str()) {
            println!(
                "[{}] WARN residual reference to old id '{}' remains -> review",
                fname, old_id
            );
        }
    }
    if let Err(e) = fs::write(path, buf) {
        println!("[{}] WRITE ERROR: {}", fname, e);
    }
}

// ---- parsing helpers (std-only) -------------------------------------------

fn collect_timer_events(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for el in elements(text, "<send") {
        if el.contains("delay=") {
            if let Some(e) = attr(&el, "event") {
                out.push(e);
            }
        }
    }
    out
}

fn initial_state(text: &str) -> String {
    // <scxml initial="X"> if present, else the first <state id="X">.
    for el in elements(text, "<scxml") {
        if let Some(v) = attr(&el, "initial") {
            return v;
        }
    }
    for el in elements(text, "<state") {
        if let Some(v) = attr(&el, "id") {
            return v;
        }
    }
    String::new()
}

fn collect_transitions(text: &str, timers: &[String]) -> Vec<Transition> {
    // Linear scan tracking the enclosing state via a stack.
    let bytes = text.as_bytes();
    let mut stack: Vec<String> = Vec::new();
    let mut out: Vec<Transition> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &text[i..];
        if rest.starts_with("</state>") {
            stack.pop();
            i += "</state>".len();
        } else if starts_open(rest, "<state") {
            let el = element_at(text, i);
            if let Some(id) = attr(&el, "id") {
                stack.push(id);
            } else {
                stack.push(String::new());
            }
            i += el.len();
        } else if starts_open(rest, "<transition") {
            let el = element_at(text, i);
            if let Some(target) = attr(&el, "target") {
                let kind = if el.contains("cond=") {
                    Kind::Cond
                } else if el
                    .split(['"'])
                    .next()
                    .map(|_| ())
                    .and_then(|_| attr(&el, "event"))
                    .map(|e| timers.iter().any(|t| *t == e))
                    .unwrap_or(false)
                {
                    Kind::Deadline
                } else {
                    Kind::Plain
                };
                out.push(Transition {
                    target,
                    kind,
                    from_state: stack.last().cloned().unwrap_or_default(),
                });
            }
            i += el.len();
        } else {
            i += 1;
        }
    }
    out
}

fn collect_finals(text: &str) -> Vec<Final> {
    let mut out = Vec::new();
    let mut search = 0usize;
    while let Some(rel) = text[search..].find("<final") {
        let start = search + rel;
        let open = element_at(text, start);
        let id = attr(&open, "id").unwrap_or_default();
        let end = match text[start..].find("</final>") {
            Some(e) => start + e,
            None => break,
        };
        let block = &text[start..end];
        let content = between(block, "<content>", "</content>")
            .unwrap_or_default()
            .trim()
            .to_string();
        let verdict = json_field(&content, "verdict");
        let reason = json_field(&content, "reason");
        let role = json_field(&content, "role");
        let _ = reason;
        out.push(Final {
            id,
            verdict,
            role,
            content,
        });
        search = end + "</final>".len();
    }
    out
}

/// Return every element string starting with `open` up to its first `>`.
fn elements(text: &str, open: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut search = 0usize;
    while let Some(rel) = text[search..].find(open) {
        let start = search + rel;
        let el = element_at(text, start);
        let len = el.len();
        out.push(el);
        search = start + len.max(1);
    }
    out
}

/// The element text from `start` (`<`) up to and including its closing `>`.
/// Quote-aware: a `>` inside a `"..."` attribute value is NOT the tag end.
/// SCXML cond attributes carry C++ expressions with literal `>`/`>=` (valid
/// XML — only `<` and `&` must be escaped in attribute values), so a naive
/// first-`>` scan would truncate the element before `target=`.
fn element_at(text: &str, start: usize) -> String {
    let bytes = text.as_bytes();
    let mut i = start;
    let mut in_quote = false;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_quote = !in_quote,
            b'>' if !in_quote => return text[start..=i].to_string(),
            _ => {}
        }
        i += 1;
    }
    text[start..].to_string()
}

/// True if `rest` begins an opening tag `name` (next char is space/newline/>/tab).
fn starts_open(rest: &str, name: &str) -> bool {
    if let Some(after) = rest.strip_prefix(name) {
        matches!(after.chars().next(), Some(' ') | Some('\n') | Some('\t') | Some('>') | Some('\r'))
    } else {
        false
    }
}

fn attr(el: &str, name: &str) -> Option<String> {
    let needle = format!("{}=\"", name);
    let p = el.find(&needle)? + needle.len();
    let rest = &el[p..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn between(s: &str, a: &str, b: &str) -> Option<String> {
    let p = s.find(a)? + a.len();
    let rest = &s[p..];
    let end = rest.find(b)?;
    Some(rest[..end].to_string())
}

fn json_field(json: &str, key: &str) -> String {
    let needle = format!("\"{}\":\"", key);
    match json.find(&needle) {
        Some(p) => {
            let rest = &json[p + needle.len()..];
            match rest.find('"') {
                Some(e) => rest[..e].to_string(),
                None => String::new(),
            }
        }
        None => String::new(),
    }
}

fn set_verdict(content: &str, new_class: &str) -> String {
    let cur = json_field(content, "verdict");
    content.replace(
        &format!("\"verdict\":\"{}\"", cur),
        &format!("\"verdict\":\"{}\"", new_class),
    )
}

/// Insert a "role" field before the closing brace (no-op if already present).
fn with_role(content: &str, _class: &str, role: &str) -> String {
    if content.contains("\"role\":") {
        return content.to_string();
    }
    let trimmed = content.trim_end();
    if let Some(stripped) = trimmed.strip_suffix('}') {
        format!("{},\"role\":\"{}\"}}", stripped, role)
    } else {
        content.to_string()
    }
}

fn rename_fail(id: &str) -> String {
    if id.contains("{$") {
        id.to_string()
    } else if let Some(rest) = id.strip_prefix("fail_") {
        format!("inconclusive_{}", rest)
    } else if id == "fail" {
        "inconclusive".to_string()
    } else {
        id.to_string()
    }
}

/// Whole-token replace (boundaries = non [A-Za-z0-9_]). Returns (new, count).
fn replace_token(text: &str, old: &str, new: &str) -> (String, usize) {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    let mut count = 0usize;
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    while i < bytes.len() {
        if text[i..].starts_with(old) {
            let before_ok = i == 0 || !is_word(bytes[i - 1]);
            let after_idx = i + old.len();
            let after_ok = after_idx >= bytes.len() || !is_word(bytes[after_idx]);
            if before_ok && after_ok {
                out.push_str(new);
                i = after_idx;
                count += 1;
                continue;
            }
        }
        let ch = text[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    (out, count)
}
