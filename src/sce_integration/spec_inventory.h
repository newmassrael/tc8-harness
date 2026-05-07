#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace tc8::sce {

// One TC8-spec test case as mined from doc/spec/case_inventory.json.
// Override fields come from doc/spec/inventory_overrides.json on two
// independent axes (defaults: expected=true, linux_known_fail=false,
// empty reason strings):
//   - `expected:false` (+ `defer_reason`) — spec gap. The harness
//     intentionally cannot cover this case (impossible against any
//     reasonable DUT, e.g. wall-time-permanent-deferred shapes).
//     Counted as a gap by the `--vs-spec` coverage report.
//   - `linux_known_fail:true` (+ `linux_known_fail_ref`) — the case
//     fails on the Linux DUT due to platform-specific RFC deviations,
//     but a strict-RFC DUT under the same harness lands on pass.
//     Kept ACTIVE in coverage reports so spec coverage stays honest;
//     CI/smoke skip lists filter it via `--exclude-linux-known-fail`.
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
    bool linux_known_fail = false;
    std::string linux_known_fail_ref;
};

// Loads doc/spec/case_inventory.json + doc/spec/inventory_overrides.json
// and exposes them indexed by canonical (UPPER) case_id. Failure cases:
// missing/malformed files surface as std::nullopt with the error written
// to *err.
class SpecInventory {
public:
    static std::optional<SpecInventory> load(const std::string &inventory_path,
                                             const std::string &overrides_path,
                                             std::string *err);

    // Canonicalise a case_id for comparison: upper-case + strip the
    // harness-only `_NEG` and `_LINUX_KNOWN_FAIL` suffixes. Spec IDs
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
