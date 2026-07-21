#pragma once

#include <string>
#include <string_view>

namespace tc8::sce {

// ============================================================================
// Conformance verdict — the single source of truth for the TC8 verdict
// taxonomy (ISO/IEC 9646 / TTCN-3 model).
//
// Every place that needs the verdict classes, their canonical names, or their
// process exit codes derives from `VerdictClass` and the mapping functions
// below — there is no second copy in C++:
//   - the runner builds a `Verdict` from a case's donedata (verdictFromDonedata);
//   - the CLI prints `Verdict::str()` and exits with `Verdict::exitCode()`.
//
// Two cross-language consumers necessarily mirror the class *names*; both are
// annotated in-place to point back here as the canonical definition:
//   - dut/env/smoke-test.sh   (Bash: matches "pass" / "inconclusive|error")
//   - tools/verdict_drift_audit.py  (Python: VALID_CLASSES)
// ============================================================================
// The taxonomy lives in verdict_taxonomy.def — the single source, also parsed
// by tools/gen_verdict_taxonomy.py to generate the Python (audit) and Bash
// (smoke gate) mirrors. Roles are a no-op in C++: the runtime reads the class
// from donedata; role->class is an audit-time concern (docs/verdict_policy.md).
#define TC8_VERDICT_ROLE(name, cls)

enum class VerdictClass {
#define TC8_VERDICT_CLASS(Enum, name, code) Enum,
#include "../../verdict_taxonomy.def"
#undef TC8_VERDICT_CLASS
};

// Canonical lowercase name carried in the SCXML donedata `verdict` field and
// printed on the harness `verdict  :` line.
constexpr std::string_view verdictClassName(VerdictClass c) {
    switch (c) {
#define TC8_VERDICT_CLASS(Enum, name, code) case VerdictClass::Enum: return name;
#include "../../verdict_taxonomy.def"
#undef TC8_VERDICT_CLASS
    }
    return "running";
}

// Inverse of `verdictClassName`. Any unrecognised name maps to `Fail`
// (fail-closed on unknowns) — the donedata audit forbids unknown classes from
// ever being committed, so this only guards against corruption at runtime.
constexpr VerdictClass verdictClassFromName(std::string_view name) {
#define TC8_VERDICT_CLASS(Enum, name, code) if (n == name) return VerdictClass::Enum;
    const std::string_view n = name;
#include "../../verdict_taxonomy.def"
#undef TC8_VERDICT_CLASS
    return VerdictClass::Fail;  // "fail" and anything unknown
}

// Process exit class so the smoke harness / CI can distinguish a real DUT
// FAIL from a run that did not conclude. `Running` is fail-closed: a final
// state that carries no verdict is an authoring defect, not a pass.
constexpr int verdictExitCode(VerdictClass c) {
    switch (c) {
#define TC8_VERDICT_CLASS(Enum, name, code) case VerdictClass::Enum: return code;
#include "../../verdict_taxonomy.def"
#undef TC8_VERDICT_CLASS
    }
    return 1;
}

#undef TC8_VERDICT_ROLE

// A conformance verdict: a class plus an optional human-readable reason.
struct Verdict {
    VerdictClass cls = VerdictClass::Running;
    std::string  reason;

    // Flat wire form the smoke harness greps for: "<class>" when there is no
    // reason, "<class>:<reason>" otherwise.
    std::string str() const {
        std::string out{verdictClassName(cls)};
        if (!reason.empty()) {
            out.push_back(':');
            out.append(reason);
        }
        return out;
    }

    int exitCode() const { return verdictExitCode(cls); }
};

// ----------------------------------------------------------------------------
// Donedata parsing (W3C SCXML 5.5)
// ----------------------------------------------------------------------------

// Extract the value of a top-level string field `key` from the flat JSON
// object `json`, or an empty string when absent. Deliberately minimal: the
// donedata it parses is machine-emitted by the SCE codegen with the fixed
// shape {"verdict":"<class>"[,"reason":"<reason>"]}, where both values are
// plain identifiers (never escaped), so this avoids pulling a full JSON
// parser into every case translation unit that includes the runner (mirrors
// spec_inventory's hand-rolled approach and dodges the nlohmann find_package
// gap on this header). A backslash still escapes the following byte.
inline std::string jsonStringField(std::string_view json, std::string_view key) {
    std::string needle;
    needle.reserve(key.size() + 2);
    needle.push_back('"');
    needle.append(key);
    needle.push_back('"');
    const auto kpos = json.find(needle);
    if (kpos == std::string_view::npos) return {};
    auto i = json.find(':', kpos + needle.size());
    if (i == std::string_view::npos) return {};
    ++i;
    while (i < json.size() && (json[i] == ' ' || json[i] == '\t')) ++i;
    if (i >= json.size() || json[i] != '"') return {};
    ++i;  // skip opening quote
    std::string out;
    while (i < json.size() && json[i] != '"') {
        if (json[i] == '\\' && i + 1 < json.size()) ++i;
        out.push_back(json[i]);
        ++i;
    }
    return out;
}

// Decode one layer of JSON string encoding. W3C SCXML 5.5 treats an inline
// `<content>` literal as a *string* value, so the SCE codegen's
// `emitContentLiteral` round-trips the authored `{"verdict":...}` object
// through `ScriptValue{string}` -> `scriptValueToJsonString`, and the engine
// stashes it quoted-and-escaped (`"{\"verdict\":\"fail\",...}"`). Strip that
// wrapper to recover the inner object. A value that is already a bare object
// (leading `{`) is returned unchanged, so both shapes parse. This double
// encoding is forced by the `datamodel="null"` AOT path (no JS engine, so
// donedata content can only be a string literal); it is not a defect.
inline std::string jsonUnquote(std::string_view s) {
    std::size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\n' || s[b] == '\r')) ++b;
    if (b >= s.size() || s[b] != '"') return std::string(s);
    std::string out;
    for (std::size_t i = b + 1; i < s.size() && s[i] != '"'; ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            switch (s[++i]) {
                case 'n': out.push_back('\n'); break;
                case 't': out.push_back('\t'); break;
                case 'r': out.push_back('\r'); break;
                default:  out.push_back(s[i]); break;  // \" \\ \/ -> literal
            }
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

// Build a `Verdict` from a stashed donedata payload. Empty donedata (a
// non-final state, or a final with no donedata) yields the `Running`
// sentinel. Decodes the W3C string-content wrapper first (see `jsonUnquote`).
inline Verdict verdictFromDonedata(std::string_view donedata) {
    const std::string obj = jsonUnquote(donedata);
    const std::string cls = jsonStringField(obj, "verdict");
    if (cls.empty()) return Verdict{VerdictClass::Running, {}};
    return Verdict{verdictClassFromName(cls), jsonStringField(obj, "reason")};
}

}  // namespace tc8::sce
