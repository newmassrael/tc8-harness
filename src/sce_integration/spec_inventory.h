#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace tc8::sce {

// One TC8-spec test case as mined from docs/spec/case_inventory.json.
// Override fields come from docs/spec/inventory_overrides.json on two
// independent axes (defaults: expected=true, platform_known_fail=false,
// empty reason strings):
//   - `expected:false` (+ `defer_reason`) — spec gap. The harness
//     intentionally cannot cover this case (impossible against any
//     reasonable DUT, e.g. wall-time-permanent-deferred shapes).
//     Counted as a gap by the `--vs-spec` coverage report.
//   - `platform_known_fail:true` (+ `platform_known_fail_ref`) — the
//     case fails on the overrides file's target DUT platform due to
//     platform-specific RFC deviations, but a strict-RFC DUT under the
//     same harness lands on pass. Each per-DUT overrides JSON (the
//     default docs/spec/inventory_overrides.json describes the Linux
//     reference DUT; --inventory-overrides swaps in another platform's
//     file) owns its platform's entries. Kept ACTIVE in coverage
//     reports so spec coverage stays honest; CI/smoke skip lists
//     filter it via `--exclude-platform-known-fail`.
// Both `id` and `category` are stored verbatim from the spec body —
// case-folding to upper case for comparison against harness-registered
// IDs is the consumer's job (see SpecInventory::canonicalise).
struct SpecCase {
    std::string id;
    std::string category;
    std::string section;
    std::string split;
    int line = 0;
    bool expected = true;
    std::string defer_reason;
    bool platform_known_fail = false;
    std::string platform_known_fail_ref;
    // Third (independent) axis: `timing_serial:true` (+ `timing_serial_ref`)
    // marks a case whose verdict measures a sub-second inter-frame interval
    // (a strict `frame_delta_within_us` cadence window) — the reference DUT
    // can only meet it when it is NOT CPU-starved, so it MUST run uncontended
    // (smoke `--workers 1`), mirroring how a conformance lab measures timing
    // on dedicated DUT hardware. Stays ACTIVE in coverage (it is a real,
    // passing case); CI routes it to a serial lane via `--only-serial` /
    // away from the parallel lane via `--exclude-serial`.
    bool timing_serial = false;
    std::string timing_serial_ref;
    // Fourth (independent) axis: `neg_expected:false` (+ `reason`) marks the
    // case's harness-only `_NEG` self-validation sibling as inapplicable on the
    // overrides file's target DUT, WITHOUT deferring the positive base case. It
    // exists because a `_NEG` mutation test is only meaningful where the fault
    // can be injected: the §4.2 ARP `_NEG` cases drive an lwIP-fixture egress
    // flavor (UT 0x18 OpSetArpFlavor), so on the Linux reference DUT — whose
    // kernel emits §4.2 ARP with no fault seam — the arm is inert and the
    // negative would land on its fail_compliant branch. The base `expected`
    // axis cannot express this: `expected` lives on the canonical (base) id, so
    // `ARP_07` and `ARP_07_NEG` share one SpecCase and deferring it would drop
    // the passing positive too. `neg_expected` is consulted by `--list-cases`
    // ONLY for a registered case whose id ends in `_NEG`; the positive base is
    // unaffected and stays in coverage. Defaults true (the autoconf / DHCPv4
    // `_NEG` cases are firmware-faulted on tc8-dut, so they run on Linux).
    bool neg_expected = true;
    std::string neg_reason;
};

// Loads docs/spec/case_inventory.json + docs/spec/inventory_overrides.json
// and exposes them indexed by canonical (UPPER) case_id. Failure cases:
// missing/malformed files surface as std::nullopt with the error written
// to *err.
class SpecInventory {
public:
    // Load the primary TC8 inventory plus zero or more EXTRA inventory
    // JSONs, merging every case into one canonical (UPPER) id map. This
    // is the out-of-tree injection hook (D5): an OEM that adds cases via
    // CMake `TC8_EXTRA_CASE_DIRS` ships a matching inventory JSON here so
    // its cases cross-check as in-spec instead of surfacing as
    // `registered-but-not-in-spec` noise in the `--vs-spec` gap report.
    //
    // Every extra file is parsed with the SAME `cases` schema as the
    // primary; its case_ids must be DISJOINT from the already-loaded set
    // (collision = loud error, mirroring the FATAL_ERROR collision policy
    // of TC8_EXTRA_CASE_DIRS — silent override would mask drift). The
    // single `overrides_path` is applied AFTER the merge, so it can defer
    // or platform-flag any case from any source. Extra files are loaded
    // in argument order; the first collision aborts with *err set.
    static std::optional<SpecInventory> load(const std::string &inventory_path,
                                             const std::vector<std::string> &extra_inventory_paths,
                                             const std::string &overrides_path,
                                             std::string *err);

    // Back-compat convenience: primary inventory + overrides, no extras.
    // Delegates to the 4-arg overload with an empty extra list.
    static std::optional<SpecInventory> load(const std::string &inventory_path,
                                             const std::string &overrides_path,
                                             std::string *err);

    // Canonicalise a case_id for comparison: upper-case + strip the
    // harness-only `_NEG` and `_PLATFORM_KNOWN_FAIL` suffixes. Spec IDs
    // (which carry mixed case like IPv4_*) round-trip through upper.
    static std::string canonicalise(std::string id);

    const std::vector<SpecCase> &cases() const {
        return cases_;
    }

    // Lookup by canonical key (UPPER). nullptr if absent.
    const SpecCase *find(const std::string &canonical_id) const;

private:
    std::vector<SpecCase> cases_;
    std::unordered_map<std::string, std::size_t> by_canonical_;
};

}  // namespace tc8::sce
