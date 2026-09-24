#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "case_suite.h"

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
//     `platform_known_fail_verdict` (optional) is the verdict the case
//     ACTUALLY lands on that platform, as a `class:reason` token —
//     `fail:dut_arp_request_after_double_injection`, or an
//     `inconclusive:...` for a deviation that produces no observation
//     at all. It exists because the excluding flag above means nothing
//     ever re-measures the claim, so a registration that has gone stale
//     (the platform was fixed, or its defect changed shape) is invisible;
//     `--list-known-fails` prints the pairs and a driver runs the set and
//     asserts them, exactly as `--list-neg-rows` does for the sixth axis.
//     Only a `fail:` verdict can account for a negative-coverage unit —
//     an `inconclusive:` one says the guard was never exercised, which
//     proves nothing about a fail final's reachability.
// Both `id` and `category` are stored verbatim from the spec body —
// case-folding to upper case for comparison against harness-registered
// IDs is the consumer's job (see SpecInventory::canonicalise).
struct SpecCase {
    // The catalog this case belongs to, in canonicalSuite() form. The primary
    // inventory is kDefaultSuite's; an extra inventory declares its own with a
    // top-level `"suite"` (absent = kDefaultSuite, as an empty
    // TC8_EXTRA_CASE_SUITES entry is). Every axis below is a property of the
    // pair (suite, id), never of the id alone — see SpecInventory::find.
    std::string suite;
    std::string id;
    std::string category;
    std::string section;
    std::string split;
    int line = 0;
    bool expected = true;
    std::string defer_reason;
    bool platform_known_fail = false;
    std::string platform_known_fail_ref;
    std::string platform_known_fail_verdict;
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
    // Fourth (independent) axis: `requires_secondary_iface:true` marks a case
    // the smoke harness must execute with a second tester interface (TC8
    // Topology 2 dual-broadcast-domain, e.g. USAGE_01). It is a harness-wiring
    // need, NOT the spec `kTopology` number (which is overloaded — UDP
    // "Topology 2" is two source hosts on ONE iface). Surfaced via
    // `--only-secondary-iface` so the smoke harness brings up the second veth
    // and passes `--interface-secondary` data-drivenly rather than by case-ID.
    bool requires_secondary_iface = false;
    // Fifth axis: `expect_overrides` — bare `--expect key=value` tokens this
    // case needs on top of the deployment identity surface every case shares.
    // They exist when a case's own STIMULUS diverges from the default (e.g. a
    // trait that subscribes to a non-default eventgroup), so the guard's
    // comparison target must follow the stimulus rather than the deployment.
    // That makes them a property of the CASE, not of the DUT deployment — the
    // same reason the four axes above live here and not in a driver.
    //
    // `runCase` appends them AFTER the driver's `--expect` tokens. Precedence
    // is therefore last-wins and needs no merge logic of its own: each
    // `applyExpectToken` assigns its field, so a later token simply overwrites
    // an earlier one. Drivers do not read this axis — they pass only the base
    // identity — which is what keeps bash and the orchestrator from being able
    // to drift on it (the property `timing_serial` already has).
    //
    // The `_ref` points at the prose (spec §, and why the stimulus diverges);
    // it is not parsed. Rationale lives in a scanned path so its § citations
    // keep their mnemosyne bindings — docs/spec/ is deliberately outside
    // Mnemosyne's surface (see mnemosyne.toml `[workspace]`), so this JSON
    // holds the VALUES only, exactly as `platform_known_fail_ref` already does.
    std::vector<std::string> expect_overrides;
    std::string expect_overrides_ref;
    // Sixth axis — the NEGATIVE row: the case's authored self-check. It replaces
    // ONE expectation with `neg_wrong_token` and asserts the harness reports
    // `neg_expect_fail`, proving the guard reacts to the value instead of
    // passing regardless. Empty for most cases — a guard that asserts DUT
    // BEHAVIOUR (must emit a correct frame / must not emit a prohibited one)
    // cannot be faulted by lying about an expectation, and those cases carry a
    // different non-vacuity disposition instead (docs/verdict_policy.md
    // Section 6; rationale + which-and-why in dut/env/negative_rows.md).
    //
    // `--negative-row` selects it, and `neg_expect_overrides` then REPLACES
    // `expect_overrides`: a negative run's stimulus is the positive one, but its
    // expectation baseline is authored separately, and conflating them would let
    // a positive override overwrite the deliberate mistake.
    //
    // ★The order base -> neg_wrong_token -> neg_expect_overrides is load-bearing,
    // which is why `load()` REJECTS a case whose neg_expect_overrides names the
    // same key as its neg_wrong_token: the override, applied last, would
    // overwrite the lie and the case would pass for the wrong reason — a silent
    // false PASS in the test-of-the-test. Nothing enforced that while the rows
    // lived in bash ("none today", by luck); one home is what makes the check
    // possible.
    std::string neg_wrong_token;
    std::string neg_expect_fail;
    std::vector<std::string> neg_expect_overrides;
    std::string neg_row_ref;

    // Seventh axis: `vsomeip_cfg` / `vsomeip_env` — the DUT-launch flavor a case
    // needs (bash CASE_VSOMEIP_VARIANT). The harness NEVER launches the DUT, so it
    // does not apply these; it only parses and EXPOSES them via
    // `--list-vsomeip-variants` for whichever driver spawns the DUT, exactly as it
    // exposes `--list-neg-rows` for a driver-applied negative row. `vsomeip_cfg` is
    // an alternate config basename (a sibling of the base vsomeip.json) or empty to
    // keep the base; `vsomeip_env` are KEY=VALUE the DUT app reads (TC8_DUT_*).
    std::string vsomeip_cfg;
    std::vector<std::string> vsomeip_env;
    std::string vsomeip_variant_ref;
    // Whether the overrides entry NAMES the seventh axis at all (either key
    // present), whatever its values. Empty values are then a declaration — "this
    // case runs against the base DUT" — not an absence. The distinction exists
    // for a same-id case in an injected suite: without its own declaration the
    // orchestrator refuses to guess whether it needs the in-tree case's flavor,
    // and this is how it says which DUT it wants, the base one included
    // (docs/tech-debt.md TD-39).
    bool vsomeip_declared = false;
};

// Loads docs/spec/case_inventory.json + docs/spec/inventory_overrides.json
// and exposes them indexed by (suite, canonical UPPER case_id). Failure
// cases: missing/malformed files surface as std::nullopt with the error
// written to *err.
//
// ONE CATALOG PER SUITE. A case's identity is (suite, id) in the registry, and
// it is (suite, id) here too: the in-tree catalog's axes describe the in-tree
// cases, and an injected suite that reuses a literal spec id is a different test
// that must not inherit them. Resolving by id alone would change that case's
// stimulus, provision its DUT for another test and excuse its failure, with
// nothing in the verdict to show it — which is why there is no id-only find().
//
// The resolution was decided per axis, not per entry, and every axis lands on
// the same answer: section, expected, platform_known_fail, timing_serial,
// requires_secondary_iface, expect_overrides, the negative row and the vsomeip
// flavor each describe either the case's own stimulus and verdict, or how one
// DUT behaves under that case's stimulus. None is a property of the id's
// spelling, so none crosses a suite boundary.
class SpecInventory {
public:
    // Load the primary TC8 inventory plus zero or more EXTRA inventory
    // JSONs. This is the out-of-tree injection hook (D5): an OEM that adds
    // cases via CMake `TC8_EXTRA_CASE_DIRS` ships a matching inventory JSON
    // here so its cases cross-check as in-spec instead of surfacing as
    // `registered-but-not-in-spec` noise in the `--vs-spec` gap report.
    //
    // Every file is parsed with the SAME `cases` schema, plus an optional
    // top-level `"suite"`. The primary file IS kDefaultSuite's catalog, so a
    // suite it declares must be that one. An extra file names the suite its
    // cases belong to (absent = kDefaultSuite, as an empty
    // TC8_EXTRA_CASE_SUITES entry is). Within one suite the case_ids must be
    // DISJOINT (collision = loud error, mirroring the FATAL_ERROR collision
    // policy of TC8_EXTRA_CASE_DIRS — silent override would mask drift);
    // across suites the same id is legal, which is what a suite is for.
    //
    // `overrides_path` empty = no overrides file; non-empty = it MUST open (an
    // unopenable path is an error, never "no overrides" — docs/tech-debt.md
    // TD-40). The single `overrides_path` is applied AFTER the merge. A bare key
    // (`"ARP_03"`) addresses kDefaultSuite's case; a qualified key
    // (`"vendorx:ARP_03"`, the same token `--case` accepts) addresses that
    // suite's. Extra files are loaded in argument order; the first error
    // aborts with *err set.
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

    // Lookup by (suite, id). `suite` is compared case-insensitively and `id` is
    // canonicalise()d here, so a registered id (variant tag and all) may be
    // passed as is. nullptr when that suite's catalog does not hold the case —
    // including when another suite's does.
    const SpecCase *find(std::string_view suite, std::string_view id) const;

    // Whether any loaded inventory file belongs to `suite` — i.e. whether there
    // is a catalog to measure that suite against at all.
    bool hasSuite(std::string_view suite) const;

private:
    static std::string key(std::string_view suite, std::string_view id);

    std::vector<SpecCase> cases_;
    std::vector<std::string> suites_;
    std::unordered_map<std::string, std::size_t> by_key_;
};

}  // namespace tc8::sce
