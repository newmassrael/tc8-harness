#include "sce_integration/spec_inventory.h"

#include "sce_integration/case_id_shape.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <regex>
#include <sstream>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace tc8::sce {

namespace {

constexpr std::string_view kPlatformKnownFailSuffix = "_PLATFORM_KNOWN_FAIL";

bool endsWith(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Read a file fully into memory. Returns std::nullopt on open failure.
std::optional<std::string> slurp(const std::string &path) {
    std::ifstream in(path);
    if (!in) {
        return std::nullopt;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Hand-rolled extractor for one quoted-string field within `block`,
// matching `"<key>"\s*:\s*"<value>"`. Returns empty string when absent.
// Keeps the parser independent of nlohmann_json so the harness builds
// in both find_package(SCE) and embed-SCE configurations (the embed
// build vendors nlohmann_json; the find_package install does not).
std::string findStringField(const std::string &block, const std::string &key) {
    const std::regex pattern("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
    std::smatch m;
    if (std::regex_search(block, m, pattern)) {
        return m[1].str();
    }
    return {};
}

int findIntField(const std::string &block, const std::string &key, int dflt = 0) {
    const std::regex pattern("\"" + key + "\"\\s*:\\s*(-?[0-9]+)");
    std::smatch m;
    if (std::regex_search(block, m, pattern)) {
        try {
            return std::stoi(m[1].str());
        } catch (...) {
            return dflt;
        }
    }
    return dflt;
}

bool findBoolField(const std::string &block, const std::string &key, bool dflt) {
    const std::regex pattern("\"" + key + "\"\\s*:\\s*(true|false)");
    std::smatch m;
    if (std::regex_search(block, m, pattern)) {
        return m[1].str() == "true";
    }
    return dflt;
}

// Reads a `"key": ["a", "b"]` array of strings; empty when the key is absent
// or the array is empty. Elements are taken verbatim — the one consumer
// (`expect_overrides`) holds bare `key=value` --expect tokens, which the
// --expect schema (tc8_expect_keys.def) already constrains to characters
// needing no JSON escaping. The `[^\]]*` body match likewise assumes no ']'
// inside an element, which that same schema guarantees. Flat and
// regex-based, matching the field readers above.
std::vector<std::string> findStringArrayField(const std::string &block,
                                              const std::string &key) {
    const std::regex pattern("\"" + key + "\"\\s*:\\s*\\[([^\\]]*)\\]");
    std::smatch m;
    if (!std::regex_search(block, m, pattern)) {
        return {};
    }
    const std::string body = m[1].str();
    const std::regex item("\"([^\"]*)\"");
    std::vector<std::string> out;
    for (auto it = std::sregex_iterator(body.begin(), body.end(), item);
         it != std::sregex_iterator(); ++it) {
        out.push_back((*it)[1].str());
    }
    return out;
}

// Walk a JSON-array body and yield each top-level `{...}` block as a string.
// Tracks brace depth to handle nested objects safely; quoted strings opt
// out of the brace counter so a `}` inside a string doesn't terminate
// the block early.
std::vector<std::string> splitJsonObjectArray(const std::string &arr_body) {
    std::vector<std::string> out;
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    std::string cur;
    for (char c : arr_body) {
        if (in_string) {
            cur.push_back(c);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        if (c == '"') {
            in_string = true;
            cur.push_back(c);
            continue;
        }
        if (c == '{') {
            if (depth == 0) {
                cur.clear();
            }
            cur.push_back(c);
            ++depth;
            continue;
        }
        if (c == '}') {
            cur.push_back(c);
            --depth;
            if (depth == 0) {
                out.push_back(cur);
                cur.clear();
            }
            continue;
        }
        if (depth > 0) {
            cur.push_back(c);
        }
    }
    return out;
}

// Locate the JSON-array body for a given top-level array key inside the
// document, returning the substring between the matching `[` and `]`.
// Returns empty string when the key is absent or malformed.
std::string extractArrayBody(const std::string &doc, const std::string &key) {
    const std::regex marker("\"" + key + "\"\\s*:\\s*\\[");
    std::smatch m;
    if (!std::regex_search(doc, m, marker)) {
        return {};
    }
    std::size_t pos = static_cast<std::size_t>(m.position(0)) +
                      static_cast<std::size_t>(m.length(0));
    int depth = 1;
    bool in_string = false;
    bool escaped = false;
    std::string body;
    for (std::size_t i = pos; i < doc.size(); ++i) {
        char c = doc[i];
        if (in_string) {
            body.push_back(c);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        if (c == '"') {
            in_string = true;
            body.push_back(c);
            continue;
        }
        if (c == '[') {
            ++depth;
            body.push_back(c);
            continue;
        }
        if (c == ']') {
            --depth;
            if (depth == 0) {
                return body;
            }
            body.push_back(c);
            continue;
        }
        body.push_back(c);
    }
    return {};
}

// Walk an `"overrides": { "<id>": {...}, ... }` object and yield
// (id, body) pairs. Mirrors splitJsonObjectArray but tracks the
// preceding `"<id>":` as the block's key.
std::vector<std::pair<std::string, std::string>>
splitJsonObjectMap(const std::string &doc, const std::string &key) {
    std::vector<std::pair<std::string, std::string>> out;
    const std::regex marker("\"" + key + "\"\\s*:\\s*\\{");
    std::smatch m;
    if (!std::regex_search(doc, m, marker)) {
        return out;
    }
    std::size_t pos = static_cast<std::size_t>(m.position(0)) +
                      static_cast<std::size_t>(m.length(0));
    int depth = 1;
    bool in_string = false;
    bool escaped = false;
    std::string buf;
    for (std::size_t i = pos; i < doc.size() && depth > 0; ++i) {
        char c = doc[i];
        if (in_string) {
            buf.push_back(c);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        if (c == '"') {
            in_string = true;
            buf.push_back(c);
            continue;
        }
        if (c == '{') {
            ++depth;
            buf.push_back(c);
            continue;
        }
        if (c == '}') {
            --depth;
            if (depth == 0) {
                break;
            }
            buf.push_back(c);
            continue;
        }
        buf.push_back(c);
    }
    // Now scan buf for `"<id>": { ... },` entries. The id key is a
    // quoted string immediately followed by `:` and a `{`. Reuse the
    // same depth-aware logic to slice each value-object out.
    std::string current_key;
    bool key_pending = false;
    int kdepth = 0;
    in_string = false;
    escaped = false;
    std::string val;
    auto reset_kv = [&]() {
        current_key.clear();
        val.clear();
        key_pending = false;
    };
    for (std::size_t i = 0; i < buf.size(); ++i) {
        char c = buf[i];
        if (kdepth == 0) {
            if (c == '"') {
                std::size_t j = i + 1;
                std::string id;
                bool esc2 = false;
                while (j < buf.size()) {
                    char d = buf[j];
                    if (esc2) {
                        id.push_back(d);
                        esc2 = false;
                    } else if (d == '\\') {
                        esc2 = true;
                    } else if (d == '"') {
                        break;
                    } else {
                        id.push_back(d);
                    }
                    ++j;
                }
                current_key = id;
                key_pending = true;
                i = j;  // advance past closing quote
                continue;
            }
            if (key_pending && c == '{') {
                kdepth = 1;
                val.clear();
                val.push_back(c);
                continue;
            }
            continue;  // skip whitespace, colons, commas
        }
        // kdepth > 0
        if (in_string) {
            val.push_back(c);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_string = false;
            }
            continue;
        }
        if (c == '"') {
            in_string = true;
            val.push_back(c);
            continue;
        }
        if (c == '{') {
            ++kdepth;
            val.push_back(c);
            continue;
        }
        if (c == '}') {
            --kdepth;
            val.push_back(c);
            if (kdepth == 0) {
                out.emplace_back(current_key, val);
                reset_kv();
            }
            continue;
        }
        val.push_back(c);
    }
    return out;
}

// Parse the `cases` array from one inventory JSON document, appending a
// SpecCase per entry to `out`. Single source of the inventory-row schema
// — both the primary TC8 inventory and every `--inventory-extra` file go
// through here, so a schema change touches exactly one place. Returns
// false with *err set when the `cases` array is absent (a malformed file
// must fail loudly, never silently contribute zero cases).
bool parseInventoryCases(const std::string &text, const std::string &path,
                         std::vector<SpecCase> &out, std::string *err) {
    const std::string cases_body = extractArrayBody(text, "cases");
    if (cases_body.empty()) {
        if (err != nullptr) {
            *err = "inventory " + path + " missing 'cases' array";
        }
        return false;
    }
    for (const auto &block : splitJsonObjectArray(cases_body)) {
        SpecCase sc;
        sc.id = findStringField(block, "case_id");
        if (sc.id.empty()) {
            continue;
        }
        sc.section = findStringField(block, "section");
        sc.split = findStringField(block, "split");
        sc.line = findIntField(block, "line");
        sc.category = std::string{deriveCategory(sc.id)};
        out.push_back(std::move(sc));
    }
    return true;
}

}  // namespace

std::string SpecInventory::canonicalise(std::string id) {
    std::transform(id.begin(), id.end(), id.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    if (endsWith(id, kPlatformKnownFailSuffix)) {
        id.resize(id.size() - kPlatformKnownFailSuffix.size());
    } else {
        // Strip any known harness variant tag (_NEG, _NEG2 .. _NEG8) via the
        // shared case-id shape SSOT (case_id_shape.h), so the legal tag set
        // lives in exactly ONE place (kKnownVariantTags) — a _NEG9 added there
        // is honoured here with no second edit. Maps every variant back to its
        // spec parent for both the coverage match and the section lookup.
        id = std::string{stripVariantTag(id)};
    }
    return id;
}

const SpecCase *SpecInventory::find(const std::string &canonical_id) const {
    auto it = by_canonical_.find(canonical_id);
    if (it == by_canonical_.end()) {
        return nullptr;
    }
    return &cases_[it->second];
}

std::optional<SpecInventory> SpecInventory::load(const std::string &inventory_path,
                                                 const std::string &overrides_path,
                                                 std::string *err) {
    return load(inventory_path, /*extra_inventory_paths=*/{}, overrides_path, err);
}

std::optional<SpecInventory> SpecInventory::load(
        const std::string &inventory_path,
        const std::vector<std::string> &extra_inventory_paths,
        const std::string &overrides_path,
        std::string *err) {
    auto fail = [err](std::string msg) -> std::optional<SpecInventory> {
        if (err != nullptr) {
            *err = std::move(msg);
        }
        return std::nullopt;
    };

    auto inv_text = slurp(inventory_path);
    if (!inv_text.has_value()) {
        return fail("cannot open spec inventory: " + inventory_path);
    }

    SpecInventory result;
    if (!parseInventoryCases(*inv_text, inventory_path, result.cases_, err)) {
        return std::nullopt;  // *err set by parseInventoryCases
    }

    // Merge extra inventories (D5 out-of-tree injection hook). Each
    // case_id must be DISJOINT from the already-loaded canonical set;
    // a collision is a loud error rather than a silent override so an
    // OEM inventory cannot mask drift against the primary TC8 set. The
    // `seen` set is seeded from the primary inventory and grows as each
    // extra file contributes, so collisions BETWEEN two extra files are
    // caught as well.
    std::unordered_set<std::string> seen;
    seen.reserve(result.cases_.size());
    for (const auto &sc : result.cases_) {
        seen.insert(canonicalise(sc.id));
    }
    for (const auto &extra_path : extra_inventory_paths) {
        auto extra_text = slurp(extra_path);
        if (!extra_text.has_value()) {
            return fail("cannot open extra spec inventory: " + extra_path);
        }
        std::vector<SpecCase> extra_cases;
        if (!parseInventoryCases(*extra_text, extra_path, extra_cases, err)) {
            return std::nullopt;  // *err set by parseInventoryCases
        }
        for (auto &sc : extra_cases) {
            if (!seen.insert(canonicalise(sc.id)).second) {
                return fail("extra spec inventory " + extra_path + " case '" +
                            sc.id + "' collides with an already-loaded case id");
            }
            result.cases_.push_back(std::move(sc));
        }
    }

    // Apply overrides (optional file) over the MERGED case set, so the
    // overrides JSON can defer or platform-flag a case from any source.
    // Missing file is OK; parse-failure is fatal so a malformed overrides
    // file can't silently be ignored.
    if (auto ov_text = slurp(overrides_path); ov_text.has_value()) {
        for (const auto &[id, body] : splitJsonObjectMap(*ov_text, "overrides")) {
            const std::string canon = canonicalise(id);
            const bool expected = findBoolField(body, "expected", true);
            std::string reason = findStringField(body, "reason");
            const bool platform_known_fail =
                findBoolField(body, "platform_known_fail", false);
            std::string platform_known_fail_ref =
                findStringField(body, "platform_known_fail_ref");
            const bool timing_serial =
                findBoolField(body, "timing_serial", false);
            std::string timing_serial_ref =
                findStringField(body, "timing_serial_ref");
            const bool requires_secondary_iface =
                findBoolField(body, "requires_secondary_iface", false);
            std::vector<std::string> expect_overrides =
                findStringArrayField(body, "expect_overrides");
            std::string expect_overrides_ref =
                findStringField(body, "expect_overrides_ref");
            std::string neg_wrong_token = findStringField(body, "neg_wrong_token");
            std::string neg_expect_fail = findStringField(body, "neg_expect_fail");
            std::vector<std::string> neg_expect_overrides =
                findStringArrayField(body, "neg_expect_overrides");
            std::string neg_row_ref = findStringField(body, "neg_row_ref");
            std::string vsomeip_cfg = findStringField(body, "vsomeip_cfg");
            std::vector<std::string> vsomeip_env =
                findStringArrayField(body, "vsomeip_env");
            std::string vsomeip_variant_ref =
                findStringField(body, "vsomeip_variant_ref");

            // A negative row is the (flip, expected-verdict) PAIR — half a row
            // cannot be executed, so refuse it rather than silently skipping the
            // case's self-check.
            if (neg_wrong_token.empty() != neg_expect_fail.empty()) {
                return fail("overrides: " + id +
                            " has only half a negative row (neg_wrong_token and "
                            "neg_expect_fail must be set together)");
            }
            // Only --negative-row reads neg_expect_overrides, and it refuses a
            // case with no neg_wrong_token — so this shape is unreachable data
            // that LOOKS like a negative control. 38 of the 40 bash
            // NEG_CASE_EXPECT_OVERRIDES rows were exactly this (mirrored from
            // the positive table onto cases with no row to run); rejecting it is
            // a check the bash form could not have.
            if (!neg_expect_overrides.empty() && neg_wrong_token.empty()) {
                return fail("overrides: " + id +
                            " sets neg_expect_overrides but has no negative row "
                            "(neg_wrong_token); it could never be applied");
            }
            // See SpecCase's sixth-axis note: neg_expect_overrides is applied
            // AFTER neg_wrong_token, so a shared key would overwrite the
            // deliberate mistake and the negative control would pass for the
            // wrong reason.
            if (!neg_wrong_token.empty()) {
                const std::string wrong_key =
                    neg_wrong_token.substr(0, neg_wrong_token.find('='));
                for (const auto &tok : neg_expect_overrides) {
                    if (tok.substr(0, tok.find('=')) == wrong_key) {
                        return fail("overrides: " + id + " neg_expect_overrides token '" +
                                    tok + "' collides with neg_wrong_token key '" +
                                    wrong_key +
                                    "'; the override is applied last and would "
                                    "overwrite the deliberate mistake");
                    }
                }
            }
            // Seventh-axis gates the bash array could not have: a cfg must be a
            // bare `*.json` basename (a sibling of the base cfg the driver resolves),
            // never a path; each env token must be KEY=VALUE.
            if (!vsomeip_cfg.empty() &&
                (vsomeip_cfg.find('/') != std::string::npos || vsomeip_cfg.size() < 6 ||
                 vsomeip_cfg.compare(vsomeip_cfg.size() - 5, 5, ".json") != 0)) {
                return fail("overrides: " + id + " vsomeip_cfg '" + vsomeip_cfg +
                            "' must be a bare *.json basename (sibling of the base cfg)");
            }
            for (const auto &e : vsomeip_env) {
                if (e.find('=') == std::string::npos) {
                    return fail("overrides: " + id + " vsomeip_env token '" + e +
                                "' is not KEY=VALUE");
                }
            }
            for (auto &sc : result.cases_) {
                if (canonicalise(sc.id) == canon) {
                    sc.expected = expected;
                    sc.defer_reason = std::move(reason);
                    sc.platform_known_fail = platform_known_fail;
                    sc.platform_known_fail_ref = std::move(platform_known_fail_ref);
                    sc.timing_serial = timing_serial;
                    sc.timing_serial_ref = std::move(timing_serial_ref);
                    sc.requires_secondary_iface = requires_secondary_iface;
                    sc.expect_overrides = std::move(expect_overrides);
                    sc.expect_overrides_ref = std::move(expect_overrides_ref);
                    sc.neg_wrong_token = std::move(neg_wrong_token);
                    sc.neg_expect_fail = std::move(neg_expect_fail);
                    sc.neg_expect_overrides = std::move(neg_expect_overrides);
                    sc.neg_row_ref = std::move(neg_row_ref);
                    sc.vsomeip_cfg = std::move(vsomeip_cfg);
                    sc.vsomeip_env = std::move(vsomeip_env);
                    sc.vsomeip_variant_ref = std::move(vsomeip_variant_ref);
                    break;
                }
            }
        }
    }

    result.by_canonical_.reserve(result.cases_.size());
    for (std::size_t i = 0; i < result.cases_.size(); ++i) {
        result.by_canonical_.emplace(canonicalise(result.cases_[i].id), i);
    }
    return result;
}

}  // namespace tc8::sce
