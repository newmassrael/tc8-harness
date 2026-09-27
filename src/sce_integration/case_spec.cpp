#include "sce_integration/case_spec.h"

#include <cstdint>
#include <cstdio>

namespace tc8::sce {

namespace {

// FNV-1a 64. Not a security property — the digest only has to change when its
// input does and stay put when it does not, across builds and machines, which a
// fixed, specified function gives and std::hash (implementation-defined) does not.
std::uint64_t fnv1a64(const std::string &text) {
    std::uint64_t h = 0xcbf29ce484222325ULL;
    for (const char c : text) {
        h ^= static_cast<unsigned char>(c);
        h *= 0x100000001b3ULL;
    }
    return h;
}

void appendList(std::string &out, const char *key, const std::vector<std::string> &values) {
    out += key;
    out += '=';
    for (const auto &v : values) {
        out += v;
        out += '\x1f';  // unit separator: no token can contain it
    }
    out += '\n';
}

}  // namespace

std::string executionSurface(const CaseEntry &entry, const CaseSpec &spec) {
    // One `key=value` line per field, in a fixed order, so the text — and so the
    // digest — is a function of the values alone.
    std::string text;
    const auto line = [&text](const char *key, const std::string &value) {
        text += key;
        text += '=';
        text += value;
        text += '\n';
    };
    line("deprecated", entry.deprecated ? "1" : "0");
    line("topology", std::to_string(entry.topology));
    line("bpf_group", std::to_string(static_cast<int>(entry.bpf_group)));
    line("bpf_expression", std::string{entry.bpf_expression});
    std::string ports;
    for (std::size_t i = 0; i < entry.extra_capture_udp_port_count; ++i) {
        ports += std::to_string(entry.extra_capture_udp_ports[i]) + ",";
    }
    line("extra_capture_udp_ports", ports);
    line("required_capabilities", std::to_string(entry.required_capabilities));
    line("control_plane_role", std::to_string(static_cast<int>(entry.control_plane_role)));
    // Emitted only when set. A field added after aliases began pinning digests
    // must leave every case that does not use it with the digest it had, or each
    // consumer's every alias reports CHANGED at once for a change none of them
    // runs — the noise that gets this report ignored. A case that does declare it
    // runs differently (its run is marked unperformed without --go-file), so its
    // digest moves, which is the report working.
    if (entry.dut_ready_barrier == DutReadyBarrier::kRequired) {
        line("dut_ready_barrier", "required");
    }
    if (const SpecCase *sc = spec.execution) {
        appendList(text, "expect_overrides", sc->expect_overrides);
        line("timing_serial", sc->timing_serial ? "1" : "0");
        line("requires_secondary_iface", sc->requires_secondary_iface ? "1" : "0");
        line("neg_wrong_token", sc->neg_wrong_token);
        line("neg_expect_fail", sc->neg_expect_fail);
        appendList(text, "neg_expect_overrides", sc->neg_expect_overrides);
        appendList(text, "neg_extra_wrong_tokens", sc->neg_extra_wrong_tokens);
        appendList(text, "neg_extra_expect_fails", sc->neg_extra_expect_fails);
        line("vsomeip_declared", sc->vsomeip_declared ? "1" : "0");
        line("vsomeip_cfg", sc->vsomeip_cfg);
        appendList(text, "vsomeip_env", sc->vsomeip_env);
    }
    char hex[17];
    std::snprintf(hex, sizeof hex, "%016llx", static_cast<unsigned long long>(fnv1a64(text)));
    return hex;
}

CaseSpec resolveCaseSpec(const SpecInventory &inventory, const CaseEntry &entry) {
    CaseSpec out;
    out.own = inventory.find(entry.suite, entry.id);
    out.execution =
        entry.isAlias() ? inventory.find(entry.alias_of.suite, entry.alias_of.id) : out.own;
    return out;
}

std::vector<std::string> aliasAxisConflicts(const SpecInventory &inventory,
                                            const CaseRegistry &registry) {
    std::vector<std::string> out;
    for (const auto *e : registry.listSorted(/*include_deprecated=*/true)) {
        if (!e->isAlias()) {
            continue;
        }
        const SpecCase *own = inventory.find(e->suite, e->id);
        if (own == nullptr) {
            continue;
        }
        std::string axes;
        const auto note = [&axes](const char *axis) {
            axes += axes.empty() ? "" : ", ";
            axes += axis;
        };
        if (own->timing_serial) {
            note("timing_serial");
        }
        if (own->requires_secondary_iface) {
            note("requires_secondary_iface");
        }
        if (!own->expect_overrides.empty()) {
            note("expect_overrides");
        }
        if (!own->neg_wrong_token.empty() || !own->neg_extra_wrong_tokens.empty()) {
            note("the negative row");
        }
        if (own->vsomeip_declared) {
            note("vsomeip_cfg/vsomeip_env");
        }
        if (axes.empty()) {
            continue;
        }
        out.push_back(qualifiedCaseId(e->suite, e->id) + " is an alias of " +
                      qualifiedCaseId(e->alias_of.suite, e->alias_of.id) +
                      ", but its own overrides entry declares " + axes +
                      ". An alias runs its target's stimulus, lane, negative row and DUT "
                      "flavor, so this declaration would be ignored; declare it on the "
                      "target, or author the case as a variant if it differs");
    }
    return out;
}

}  // namespace tc8::sce
