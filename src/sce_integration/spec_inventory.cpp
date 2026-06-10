#include "sce_integration/spec_inventory.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <regex>
#include <sstream>
#include <string_view>
#include <utility>

namespace tc8::sce {

namespace {

constexpr std::string_view kNegSuffix = "_NEG";
constexpr std::string_view kPlatformKnownFailSuffix = "_PLATFORM_KNOWN_FAIL";

bool endsWith(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Derive category from a spec case_id by stripping the trailing _<digits>.
// Example: ARP_07 → ARP; IPv4_HEADER_05 → IPV4_HEADER. Falls back to the
// full id if no digit-suffixed segment is present.
std::string deriveCategory(const std::string &id) {
    auto pos = id.rfind('_');
    if (pos == std::string::npos || pos + 1 >= id.size()) {
        return id;
    }
    for (std::size_t i = pos + 1; i < id.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(id[i]))) {
            return id;
        }
    }
    return id.substr(0, pos);
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

}  // namespace

std::string SpecInventory::canonicalise(std::string id) {
    std::transform(id.begin(), id.end(), id.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    if (endsWith(id, kPlatformKnownFailSuffix)) {
        id.resize(id.size() - kPlatformKnownFailSuffix.size());
    } else if (endsWith(id, kNegSuffix)) {
        id.resize(id.size() - kNegSuffix.size());
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

    const std::string cases_body = extractArrayBody(*inv_text, "cases");
    if (cases_body.empty()) {
        return fail("inventory " + inventory_path + " missing 'cases' array");
    }

    SpecInventory result;
    for (const auto &block : splitJsonObjectArray(cases_body)) {
        SpecCase sc;
        sc.id = findStringField(block, "case_id");
        if (sc.id.empty()) {
            continue;
        }
        sc.section = findStringField(block, "section");
        sc.split = findStringField(block, "split");
        sc.line = findIntField(block, "line");
        sc.category = deriveCategory(sc.id);
        result.cases_.push_back(std::move(sc));
    }

    // Apply overrides (optional file). Missing file is OK; parse-failure
    // is fatal so a malformed overrides file can't silently be ignored.
    if (auto ov_text = slurp(overrides_path); ov_text.has_value()) {
        for (const auto &[id, body] : splitJsonObjectMap(*ov_text, "overrides")) {
            const std::string canon = canonicalise(id);
            const bool expected = findBoolField(body, "expected", true);
            std::string reason = findStringField(body, "reason");
            const bool platform_known_fail =
                findBoolField(body, "platform_known_fail", false);
            std::string platform_known_fail_ref =
                findStringField(body, "platform_known_fail_ref");
            for (auto &sc : result.cases_) {
                if (canonicalise(sc.id) == canon) {
                    sc.expected = expected;
                    sc.defer_reason = std::move(reason);
                    sc.platform_known_fail = platform_known_fail;
                    sc.platform_known_fail_ref = std::move(platform_known_fail_ref);
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
