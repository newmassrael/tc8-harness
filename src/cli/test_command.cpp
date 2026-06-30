#include "cli/test_command.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <pcap/pcap.h>

#include "tc8/captured_event.h"
#include "tc8/pollable_service.h"

#include "capture/bpf_filter.h"
#include "capture/pcap_source.h"
#include "cli/expect_parser.h"
#include "cli/signal_handler.h"
#include "dissect/packet_pipeline.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/dut_control_factory.h"
#include "sce_integration/spec_inventory.h"
#include "sce_integration/test_config.h"
#include "sce_integration/verdict.h"

namespace tc8::cli {

namespace {

// Resolve a case's spec section from the loaded inventory — the SSOT
// (docs/spec/case_inventory.json, mined from the TC8 spec PDF). The
// harness deliberately does NOT store a per-case section copy in the
// case traits: a hand-authored copy drifts from the spec (cf.
// case_registry.h, where `category` is likewise derived, not stored).
// Returns "-" when the inventory is unavailable or the id is out-of-spec
// (e.g. an OEM case shipped without an extra inventory JSON).
// The single "section or '-'" fallback policy, shared by both display paths
// (specSectionFor below, which looks up by id, and the runListCases loop, which
// already holds the SpecCase from its filter pass).
std::string sectionOf(const sce::SpecCase *sc) {
    return (sc != nullptr && !sc->section.empty()) ? sc->section : std::string{"-"};
}

std::string specSectionFor(const std::optional<sce::SpecInventory> &inv, std::string_view id) {
    if (!inv.has_value()) {
        return "-";
    }
    return sectionOf(inv->find(sce::SpecInventory::canonicalise(std::string{id})));
}

}  // namespace

TestCommand::TestCommand(CLI::App &app) {
    sub_ = app.add_subcommand("test", "Run a registered TC8 test case against a live NIC");

    sub_->add_option("-c,--case", case_id_, "Case ID to run (see --list-cases)");
    sub_->add_option("-i,--interface", iface_, "NIC name, e.g. veth-tester");
    sub_->add_option("--interface-secondary", iface_secondary_,
                     "Secondary NIC for §4.7.6.5 USAGE_01 multi-iface "
                     "Topology 2. Empty = single-iface (default).");
    sub_->add_option("-t,--timeout", timeout_s_, "Maximum seconds to wait for verdict")->capture_default_str();
    sub_->add_flag("--list-cases", list_cases_, "Print registered cases grouped by category and exit");
    sub_->add_flag("--include-deprecated", list_all_, "With --list-cases, also print cases marked deprecated");
    sub_->add_flag("--vs-spec", vs_spec_,
                   "With --list-cases, emit a coverage gap report against "
                   "docs/spec/case_inventory.json instead of the per-case dump");
    sub_->add_flag("--strict", vs_spec_strict_,
                   "With --list-cases --vs-spec, exit non-zero when expected "
                   "spec cases remain unregistered");
    sub_->add_flag("--exclude-deferred", exclude_deferred_,
                   "With --list-cases (no --vs-spec), drop harness cases whose "
                   "canonical ID is marked expected:false in "
                   "docs/spec/inventory_overrides.json. Lets smoke/CI consume the "
                   "JSON as the single source of truth for spec-deferred cases.");
    sub_->add_flag("--exclude-platform-known-fail", exclude_platform_known_fail_,
                   "With --list-cases (no --vs-spec), drop harness cases whose "
                   "canonical ID is marked platform_known_fail:true in the "
                   "active inventory overrides JSON (default describes the "
                   "Linux reference DUT; --inventory-overrides selects another "
                   "platform's file) — platform-specific DUT-stack deviations "
                   "that pass on a strict-RFC DUT. Independent from "
                   "--exclude-deferred; combine for the full CI smoke skip "
                   "list.");
    auto *exclude_serial_flag = sub_->add_flag("--exclude-serial", exclude_serial_,
                   "With --list-cases (no --vs-spec), drop cases marked "
                   "timing_serial:true in the inventory overrides — sub-second "
                   "cadence measurements that the reference DUT can only meet "
                   "uncontended. The parallel (--workers N) CI lane uses this; "
                   "the serial lane uses --only-serial.");
    // Mutually exclusive: passing both would filter out every case and emit an
    // empty list — a CI lane built from that would silently run ZERO cases
    // (green by vacuity). CLI11 rejects the combination loudly instead.
    sub_->add_flag("--only-serial", only_serial_,
                   "With --list-cases (no --vs-spec), keep ONLY cases marked "
                   "timing_serial:true — CI runs these at --workers 1 so a "
                   "CPU-starved DUT does not skew the timing window.")
        ->excludes(exclude_serial_flag);
    sub_->add_flag("--only-secondary-iface", only_secondary_iface_,
                   "With --list-cases (no --vs-spec), keep ONLY cases marked "
                   "requires_secondary_iface:true (TC8 Topology 2 dual-iface). "
                   "The smoke harness lists these to bring up a second tester "
                   "veth + pass --interface-secondary data-drivenly.");
    sub_->add_option("--inventory", inventory_path_,
                     "Path to spec inventory JSON "
                     "(default: docs/spec/case_inventory.json)");
    sub_->add_option("--inventory-overrides", overrides_path_,
                     "Path to inventory overrides JSON "
                     "(default: docs/spec/inventory_overrides.json)");
    sub_->add_option("--inventory-extra", inventory_extra_paths_,
                     "Additional spec inventory JSON(s) to merge into the "
                     "--vs-spec gap report (repeatable). Out-of-tree case "
                     "injection hook: an OEM that adds cases via CMake "
                     "TC8_EXTRA_CASE_DIRS ships a matching inventory here so "
                     "its cases cross-check as in-spec. case_ids must be "
                     "disjoint from the primary TC8 inventory (collision = "
                     "error).");
    sub_->add_option("--expect", expect_tokens_,
                     "DUT-specific expected values as KEY=VALUE tokens (repeatable). "
                     "SOME/IP keys (bare): service_id, instance_id, major_version, "
                     "ttl, minor_version, eventgroup_id (hex/decimal). "
                     "ARP keys (arp.* prefix): arp.dut_iface_ip, arp.tester_ip "
                     "(IPv4 dotted), arp.dut_iface_mac (six colon-separated hex "
                     "octets). Example: --expect service_id=0xF4E7 "
                     "arp.tester_ip=172.16.0.1 arp.dut_iface_mac=aa:bb:cc:dd:ee:ff");
    sub_->add_option("--expect-extra", expect_extra_tokens_,
                     "Out-of-tree OEM KEY=VALUE tokens (repeatable), carried "
                     "verbatim into TestConfig::expect_extra_tokens for an "
                     "OEM Context's own applyTestConfig overload to parse. "
                     "Unlike --expect, these are NOT validated against the "
                     "in-tree key set — the OEM owns its key namespace.");
    sub_->add_option("--stimulus-wait", stimulus_wait_ms_,
                     "Milliseconds to wait before the first tester-side stimulus "
                     "emit (default 1500, suits tc8-dut). Widen when the DUT's "
                     "SD initial_delay exceeds ~1s.");
    sub_->add_option("--stimulus-retry", stimulus_retry_ms_,
                     "Milliseconds between consecutive stimulus emits (default 1000).");
    sub_->add_option("--stimulus-emits", stimulus_emits_,
                     "Total stimulus datagrams sent during the boot sequence "
                     "(default 2). Higher counts cost wall time but tolerate jitter.");
    sub_->add_option("--dut-control", dut_control_,
                     "DUT-control backend for seam-routed cases: 'opcode' (in-house "
                     "Upper Tester, port 30600, default) or 'testability' (AUTOSAR "
                     "Testability Protocol, port 30700). Cases driving the opcode "
                     "builders directly ignore this.")
        ->check(CLI::IsMember({"opcode", "testability"}));
    sub_->add_option("--pcap-dump", pcap_dump_path_,
                     "Write every captured frame to the given pcap file "
                     "(debug only). Empty = disabled.");
}

int TestCommand::run(std::optional<std::string> bpf_override) {
    if (list_cases_) {
        if (vs_spec_) {
            return runVsSpecReport();
        }
        return runListCases();
    }
    return runCase(std::move(bpf_override));
}

int TestCommand::runListCases() const {
    // The spec inventory (mined from the TC8 spec PDF) is the SSOT for
    // each case's section — shown in the listing below — and also drives
    // the optional filter flags. The section is DERIVED from the
    // inventory by canonical id; the harness never stores a per-case
    // section copy (it would drift; cf. case_registry.h, where `category`
    // is likewise derived, not stored).
    const bool need_filter =
        exclude_deferred_ || exclude_platform_known_fail_ || exclude_serial_ ||
        only_serial_ || only_secondary_iface_;
    const std::string inv_path = inventory_path_.empty()
        ? std::string("docs/spec/case_inventory.json")
        : inventory_path_;
    const std::string ov_path = overrides_path_.empty()
        ? std::string("docs/spec/inventory_overrides.json")
        : overrides_path_;
    std::string err;
    std::optional<sce::SpecInventory> inv =
        sce::SpecInventory::load(inv_path, inventory_extra_paths_, ov_path, &err);
    if (!inv.has_value()) {
        // The filter flags REQUIRE the inventory — fail loudly so smoke/CI
        // invocations never silently fall back to an unfiltered list.
        if (need_filter) {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 2;
        }
        // No filters requested: the section column degrades to "-" but the
        // registered list stays useful in a stripped environment.
        std::fprintf(stderr, "warning: %s (spec sections shown as '-')\n", err.c_str());
    }

    const auto entries = sce::CaseRegistry::instance().listSorted(list_all_);
    std::string_view current_suite;
    std::string_view current_category;
    std::size_t emitted = 0;
    for (const auto *e : entries) {
        const auto canon = sce::SpecInventory::canonicalise(std::string{e->id});
        const sce::SpecCase *sc = inv.has_value() ? inv->find(canon) : nullptr;
        if (need_filter) {
            // timing_serial defaults false, so a case with no override entry is
            // non-serial — --only-serial drops it, --exclude-serial keeps it.
            const bool serial = (sc != nullptr) && sc->timing_serial;
            if (only_serial_ && !serial) {
                continue;
            }
            if (exclude_serial_ && serial) {
                continue;
            }
            // requires_secondary_iface defaults false; --only-secondary-iface
            // keeps only the dual-iface (Topology 2) cases the smoke harness
            // must give a second tester veth.
            const bool secondary_iface =
                (sc != nullptr) && sc->requires_secondary_iface;
            if (only_secondary_iface_ && !secondary_iface) {
                continue;
            }
            if (sc != nullptr) {
                if (exclude_deferred_ && !sc->expected) {
                    continue;
                }
                if (exclude_platform_known_fail_ && sc->platform_known_fail) {
                    continue;
                }
            }
        }
        // Group by (suite, category) — matching listSorted's sort key. A suite
        // change prints a banner and resets the category so its header re-emits
        // inside the new suite (otherwise a category shared by two suites would
        // fold under one header). The default tc8 suite prints no banner, so
        // single-suite output stays byte-identical to before any injection.
        if (e->suite != current_suite) {
            if (!current_suite.empty()) {
                std::puts("");
            }
            if (e->suite != sce::kDefaultSuite) {
                std::printf("== suite: %.*s ==\n", static_cast<int>(e->suite.size()),
                            e->suite.data());
            }
            current_suite = e->suite;
            current_category = {};
        }
        if (e->category != current_category) {
            if (!current_category.empty()) {
                std::puts("");
            }
            std::printf("%.*s\n", static_cast<int>(e->category.size()), e->category.data());
            current_category = e->category;
        }
        const std::string section = sectionOf(sc);
        const char *tag = e->deprecated ? " [deprecated]" : "";
        // Non-default suites print the qualified "suite:id" so the listed token
        // is the exact `--case` arg to run it; the in-tree suite stays bare
        // (output byte-identical to before any suite injection).
        std::string display_id;
        if (e->suite != sce::kDefaultSuite) {
            display_id.assign(e->suite);
            display_id.append(":");
        }
        display_id.append(e->id);
        std::printf("  %-28.*s  §%-10.*s %.*s%s\n",
                    static_cast<int>(display_id.size()), display_id.data(),
                    static_cast<int>(section.size()), section.data(),
                    static_cast<int>(e->description.size()), e->description.data(), tag);
        ++emitted;
    }
    if (only_serial_) {
        std::printf("\n%zu timing_serial case(s) listed.\n", emitted);
    } else if (exclude_deferred_ || exclude_platform_known_fail_ || exclude_serial_) {
        std::string note;
        if (exclude_deferred_) {
            note = "deferred";
        }
        if (exclude_platform_known_fail_) {
            note += note.empty() ? "" : "+";
            note += "platform_known_fail";
        }
        if (exclude_serial_) {
            note += note.empty() ? "" : "+";
            note += "timing_serial";
        }
        std::printf("\n%zu case(s) listed (%s excluded).\n", emitted, note.c_str());
    } else {
        std::printf("\n%zu case(s) registered.\n", sce::CaseRegistry::instance().size());
    }
    return 0;
}

int TestCommand::runVsSpecReport() const {
    const std::string inv_path = inventory_path_.empty()
        ? std::string("docs/spec/case_inventory.json")
        : inventory_path_;
    const std::string ov_path = overrides_path_.empty()
        ? std::string("docs/spec/inventory_overrides.json")
        : overrides_path_;

    std::string err;
    auto inv_opt =
        sce::SpecInventory::load(inv_path, inventory_extra_paths_, ov_path, &err);
    if (!inv_opt.has_value()) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 2;
    }
    const auto &inv = *inv_opt;

    // Build canonical-ID set of registered cases (strip _NEG /
    // _PLATFORM_KNOWN_FAIL so harness variant tags don't masquerade as
    // distinct spec entries).
    std::set<std::string> registered_canon;
    for (const auto *e : sce::CaseRegistry::instance().listSorted(/*include_deprecated=*/true)) {
        registered_canon.insert(sce::SpecInventory::canonicalise(std::string{e->id}));
    }

    // Group spec cases by category for the per-category breakdown.
    struct CategoryRow {
        std::vector<const sce::SpecCase *> registered;
        std::vector<const sce::SpecCase *> missing;
        std::vector<const sce::SpecCase *> deferred;
        std::vector<const sce::SpecCase *> unregistered_deferred;
    };
    std::unordered_map<std::string, CategoryRow> rows;
    std::vector<std::string> category_order;
    for (const auto &sc : inv.cases()) {
        const std::string canon = sce::SpecInventory::canonicalise(sc.id);
        auto it = rows.find(sc.category);
        if (it == rows.end()) {
            category_order.push_back(sc.category);
            it = rows.emplace(sc.category, CategoryRow{}).first;
        }
        const bool is_registered = registered_canon.count(canon) > 0;
        const bool is_deferred = !sc.expected;
        if (is_registered) {
            it->second.registered.push_back(&sc);
            if (is_deferred) {
                it->second.deferred.push_back(&sc);
            }
        } else if (is_deferred) {
            it->second.unregistered_deferred.push_back(&sc);
        } else {
            it->second.missing.push_back(&sc);
        }
    }
    std::sort(category_order.begin(), category_order.end());

    int total_expected = 0;
    int total_registered = 0;
    int total_missing = 0;
    int total_deferred = 0;
    for (const auto &cat : category_order) {
        const auto &row = rows.at(cat);
        const int expected_n = static_cast<int>(row.registered.size() + row.missing.size());
        const int registered_n = static_cast<int>(row.registered.size());
        const int missing_n = static_cast<int>(row.missing.size());
        const int deferred_n = static_cast<int>(row.deferred.size() + row.unregistered_deferred.size());
        total_expected += expected_n;
        total_registered += registered_n;
        total_missing += missing_n;
        total_deferred += deferred_n;

        const char *status = "[OK]   ";
        if (missing_n > 0) {
            status = "[GAP]  ";
        } else if (deferred_n > 0) {
            status = "[DEFER]";
        }
        std::printf("%s %-44s  %d / %d", status, cat.c_str(), registered_n, expected_n);
        if (deferred_n > 0) {
            std::printf("  (%d deferred)", deferred_n);
        }
        std::printf("\n");
        if (missing_n > 0) {
            std::printf("            missing : ");
            for (std::size_t i = 0; i < row.missing.size(); ++i) {
                std::printf("%s%s", row.missing[i]->id.c_str(),
                            i + 1 < row.missing.size() ? ", " : "");
            }
            std::printf("\n");
        }
        if (!row.deferred.empty() || !row.unregistered_deferred.empty()) {
            std::printf("            deferred: ");
            std::vector<const sce::SpecCase *> defs;
            defs.insert(defs.end(), row.deferred.begin(), row.deferred.end());
            defs.insert(defs.end(), row.unregistered_deferred.begin(), row.unregistered_deferred.end());
            for (std::size_t i = 0; i < defs.size(); ++i) {
                std::printf("%s%s", defs[i]->id.c_str(), i + 1 < defs.size() ? ", " : "");
            }
            std::printf("\n");
        }
    }

    // Surface registered-but-not-in-spec entries (typically harness
    // variant tags with no parent in the spec body — should be 0 once
    // canonicalise() does its job).
    std::set<std::string> spec_canon;
    for (const auto &sc : inv.cases()) {
        spec_canon.insert(sce::SpecInventory::canonicalise(sc.id));
    }
    std::vector<std::string> registered_only;
    for (const auto *e : sce::CaseRegistry::instance().listSorted(true)) {
        std::string canon = sce::SpecInventory::canonicalise(std::string{e->id});
        if (spec_canon.count(canon) == 0) {
            registered_only.push_back(std::string{e->id});
        }
    }
    if (!registered_only.empty()) {
        std::printf("\nregistered-but-not-in-spec (harness-only) : %zu\n", registered_only.size());
        for (const auto &id : registered_only) {
            std::printf("  - %s\n", id.c_str());
        }
    }

    const double coverage = total_expected == 0
        ? 0.0
        : 100.0 * static_cast<double>(total_registered) / static_cast<double>(total_expected);
    std::printf("\nSummary: %d / %d expected (%.1f%% coverage); missing=%d, deferred=%d\n",
                total_registered, total_expected, coverage, total_missing, total_deferred);

    if (vs_spec_strict_ && total_missing > 0) {
        return 1;
    }
    return 0;
}

int TestCommand::runCase(std::optional<std::string> bpf_override) {
    if (case_id_.empty()) {
        std::fprintf(stderr, "error: --case <ID> is required (try --list-cases)\n");
        return 2;
    }
    if (iface_.empty()) {
        std::fprintf(stderr, "error: --interface <NIC> is required\n");
        return 2;
    }

    // Accept an optional "suite:" qualifier (e.g. "vendorx:SOMEIPSRV_RPC_01"). An
    // unqualified id resolves only if it is unique across suites; a cross-suite
    // id (same id in tc8 + an injected catalog) is ambiguous and must be
    // qualified. The in-tree single-suite case is unaffected (unique id).
    const sce::CaseEntry *entry = nullptr;
    const auto suite_sep = case_id_.find(':');
    if (suite_sep != std::string::npos) {
        const std::string_view qualified{case_id_};
        entry = sce::CaseRegistry::instance().find(qualified.substr(0, suite_sep),
                                                   qualified.substr(suite_sep + 1));
    } else {
        entry = sce::CaseRegistry::instance().find(case_id_);
    }
    if (entry == nullptr) {
        std::fprintf(stderr,
                     "error: unknown or ambiguous case '%s' (try --list-cases; "
                     "qualify a cross-suite id as suite:ID)\n",
                     case_id_.c_str());
        return 2;
    }
    if (entry->deprecated) {
        std::fprintf(stderr, "error: case '%s' is marked deprecated in the spec\n", case_id_.c_str());
        return 2;
    }

    const std::string bpf = capture::bpf::resolveCaptureFilter(
        bpf_override, entry->bpf_expression, entry->bpf_group,
        entry->extra_capture_udp_ports, entry->extra_capture_udp_port_count);

    // Spec section is derived from the inventory (the SSOT), not stored on
    // the case — see runListCases() / case_registry.h. Best-effort here: a
    // missing inventory just renders the section as "-".
    const std::string inv_path = inventory_path_.empty()
        ? std::string("docs/spec/case_inventory.json")
        : inventory_path_;
    const std::string ov_path = overrides_path_.empty()
        ? std::string("docs/spec/inventory_overrides.json")
        : overrides_path_;
    std::string inv_err;
    const auto inv =
        sce::SpecInventory::load(inv_path, inventory_extra_paths_, ov_path, &inv_err);
    const std::string section = specSectionFor(inv, entry->id);

    std::printf("case     : %.*s  (§%s)\n", static_cast<int>(entry->id.size()), entry->id.data(),
                section.c_str());
    std::printf("source   : test live (%s)\n", iface_.c_str());
    std::printf("bpf      : %s\n", bpf.c_str());

    auto src = capture::PcapSource::openLive(iface_, /*snaplen=*/65535,
                                             /*read_timeout_ms=*/100);
    src->applyBpf(bpf);
    SignalGuard guard(*src);
    const int dlt = src->datalink();

    // §4.7.6.5 USAGE_01 second pcap source. Same BPF + snaplen as the
    // primary so both ifaces produce structurally identical capture
    // events; the only difference is the iface they ride on. The
    // harness round-robins both in the dispatch loop below so SCXML
    // sees a time-ordered stream covering BOTH broadcast domains.
    // SignalGuard is wired to the primary only — the second source's
    // teardown rides on its destructor at scope exit, which is enough
    // for graceful Ctrl-C since `breakLoop` on the primary already
    // exits the dispatch loop before the secondary's next dispatch.
    std::unique_ptr<capture::PcapSource> src2;
    int dlt2 = DLT_EN10MB;
    if (!iface_secondary_.empty()) {
        src2 = capture::PcapSource::openLive(iface_secondary_,
                                              /*snaplen=*/65535,
                                              /*read_timeout_ms=*/100);
        src2->applyBpf(bpf);
        dlt2 = src2->datalink();
    }

    pcap_dumper_t *dumper = nullptr;
    if (!pcap_dump_path_.empty()) {
        dumper = pcap_dump_open(src->handle(), pcap_dump_path_.c_str());
        if (dumper == nullptr) {
            std::fprintf(stderr, "pcap_dump_open('%s') failed: %s\n",
                         pcap_dump_path_.c_str(), pcap_geterr(src->handle()));
            return 1;
        }
    }

    ::tc8::TestConfig config{};
    // OEM passthrough tokens ride into the config verbatim — an out-of-tree
    // Context parses them in its own applyTestConfig overload. The strict
    // --expect loop below keeps owning the closed in-tree key set.
    config.expect_extra_tokens = expect_extra_tokens_;
    for (const auto &tok : expect_tokens_) {
        // Try each protocol's parser; the first that recognises the token
        // wins. ARP's parser short-circuits on the `arp.` prefix so SOME/IP
        // keys never reach it. A token unrecognised by both is a CLI error.
        if (applyExpectToken(tok, config.arp)) {
            continue;
        }
        if (applyExpectToken(tok, config.dut)) {
            continue;
        }
        if (applyExpectToken(tok, config.arp_stimulus)) {
            continue;
        }
        if (applyExpectToken(tok, config.icmpv4)) {
            continue;
        }
        if (applyExpectToken(tok, config.ipv4)) {
            continue;
        }
        if (applyExpectToken(tok, config.dhcpv4)) {
            continue;
        }
        if (!applyExpectToken(tok, config.someip)) {
            std::fprintf(stderr,
                         "error: --expect token '%s' is not a recognised "
                         "KEY=VALUE pair\n",
                         tok.c_str());
            return 2;
        }
    }
    if (stimulus_wait_ms_.has_value()) {
        config.stimulus_timing.initial_wait = std::chrono::milliseconds(*stimulus_wait_ms_);
    }
    if (stimulus_retry_ms_.has_value()) {
        config.stimulus_timing.retry_interval = std::chrono::milliseconds(*stimulus_retry_ms_);
    }
    if (stimulus_emits_.has_value()) {
        config.stimulus_timing.total_emits = *stimulus_emits_;
    }
    config.dut_control_backend = (dut_control_ == "testability")
                                     ? sce::DutControlBackend::kTestability
                                     : sce::DutControlBackend::kOpcode;

    std::unique_ptr<sce::ITestRunner> runner = entry->factory(config);

    // Tier-2 DUT-control backend (--dut-control). Owned here for the run's
    // lifetime and forwarded to seam-routed stimulus; cases that drive the
    // opcode builders directly never touch it. Built once, not per-case.
    std::unique_ptr<sce::IDutControl> dut_control = sce::makeDutControl(config);

    // Tier-2 2b#4 capability-skip gate. A case may declare the DUT-control
    // capabilities it needs (TestCaseTraits<>::kRequiredCapabilities, mirrored
    // into CaseEntry). If the selected backend / DUT lacks any of them the case
    // cannot run meaningfully there — the standard AUTOSAR testability backend
    // exposes no kernel state-probe SP, and the kernel-stack reference DUT
    // implements no fixture fault seam (its OpQueryCapabilities bitmap omits
    // OpSetEgressFlavor / OpSetIngressFlavor, so capabilities() omits
    // kCapEgressFault / kCapIngressFault and the `_NEG` cases skip here). Emit a
    // skip verdict (NOT a fail) and a distinct
    // exit code so smoke-test.sh routes it to the existing conditioning-skip
    // ledger. Only consulted for a case that declares a requirement: capabilities()
    // may probe the DUT (OpQueryCapabilities) to resolve DUT-derived fault caps,
    // so a case needing nothing pays no extra I/O and is never gated.
    if (entry->required_capabilities != 0U) {
        if (const std::uint32_t missing =
                entry->required_capabilities & ~dut_control->capabilities();
            missing != 0U) {
            // A missing DUT-derived fault cap has two causes that must NOT be
            // conflated: the DUT answered OpQueryCapabilities and genuinely lacks
            // the seam (a real N/A skip), OR the bitmap could not be resolved
            // (DUT unreachable / pre-0x16) — for a case that NEEDS the seam that
            // is a test-system non-conclusion, not an N/A. Surfacing the latter
            // as `error` (gating on a strict driver, visible in JUnit either way)
            // keeps a `_NEG` proof from silently turning green when it could not
            // even determine whether the fault was injectable.
            if ((missing & sce::kDutDerivedCaps) != 0U && !dut_control->faultCapsResolved()) {
                std::printf("verdict  : error:dut_capability_query_unresolved_0x%x_on_%s\n",
                            static_cast<unsigned>(missing), dut_control->backendName());
                return ::tc8::sce::verdictExitCode(::tc8::sce::VerdictClass::Error);
            }
            std::printf("verdict  : skip:requires_capability_0x%x_unavailable_on_%s\n",
                        static_cast<unsigned>(missing), dut_control->backendName());
            return 2;  // distinct from 0 (pass) / 1 (fail): capability-skip
        }
    }

    dissect::PacketPipeline pipeline([&runner](const ::tc8::CapturedEvent &ev) { runner->onCaptured(ev); });
    // Wire pcap's timestamp precision into the dissector so
    // TcpFrame.observed_ts_us stays in microseconds for both live
    // (default MICRO) and offline-replay (NANO) capture sources.
    pipeline.setTstampPrecision(src->tstampPrecision());

    // When pcap_dump is enabled, wrap the frame callback to also write to
    // disk. Done as a separate callback inside dispatch(), below.

    // Tester-side stimulus for cases whose Test Procedure starts with a
    // TESTER-initiated request (e.g. FORMAT_12/13 FindService). Called
    // after BPF is applied so kernel capture is armed before the DUT's
    // solicited response arrives. No-op for cases without a stimulus hook.
    runner->kickStimulus(iface_, *dut_control);

    // Initialize the state machine AFTER stimulus so SCXML delay-based
    // deadline timers arm fresh. Without this split the stimulus's wall
    // time would count against the listen window.
    runner->start();

    // Run-scoped background services (e.g. an ArpResponder answering the DUT's
    // ARP for a tester-spoofed source IP) the case adopted during kickStimulus.
    // Drained inline in the capture loops below on this single thread — no worker
    // thread, no capture/emit concurrency. Empty for every case that adopts none
    // (the vast majority), so the drains are then no-ops. Pointers borrowed; the
    // runner owns the objects for the run.
    const std::vector<::tc8::IPollableService *> services = runner->pollableServices();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_s_);

    // Evidence Export (Option 3) — every frame appended to the saved pcap
    // gets a monotonic index, surfaced to the runner BEFORE
    // pipeline.processFrame so the resulting transition (if any) can be
    // correlated back. -1 stays the default (no pcap dumper, or frame
    // dropped pre-dump); transitions recorded at -1 surface as
    // verdict-decider-not-retained case notes via the site walker.
    int next_pcap_frame_idx = 0;

    while (!SignalGuard::stopRequested() && !runner->isDone() && std::chrono::steady_clock::now() < deadline) {
        const int n = src->dispatch(
            /*max_frames=*/-1,
            [&](const pcap_pkthdr &hdr, const u_char *data) {
                int this_frame_idx = -1;
                if (dumper != nullptr) {
                    pcap_dump(reinterpret_cast<u_char *>(dumper), &hdr, data);
                    this_frame_idx = next_pcap_frame_idx++;
                }
                runner->setNextPcapFrameIdx(this_frame_idx);
                pipeline.processFrame(hdr, data, dlt);
            });
        if (n == -2) {
            break;
        }
        if (n < 0) {
            std::fprintf(stderr, "dispatch error: %s\n", src->lastError());
            return 1;
        }
        // §4.7.6.5 USAGE_01: drain the secondary source within the
        // same outer-loop iteration so frames arriving on TIface-1
        // interleave with primary-iface frames in the order they hit
        // the wire. pcap kernel ring is per-handle so each call picks
        // up only its iface's queue; round-robin within the loop is
        // the simplest serialiser and the SCXML's time-ordered guards
        // tolerate the ~20 ms quanta cleanly.
        int n2 = 0;
        if (src2) {
            n2 = src2->dispatch(
                /*max_frames=*/-1,
                [&](const pcap_pkthdr &hdr, const u_char *data) {
                    int this_frame_idx = -1;
                    if (dumper != nullptr) {
                        pcap_dump(reinterpret_cast<u_char *>(dumper), &hdr, data);
                        this_frame_idx = next_pcap_frame_idx++;
                    }
                    runner->setNextPcapFrameIdx(this_frame_idx);
                    pipeline.processFrame(hdr, data, dlt2);
                });
            if (n2 == -2) {
                break;
            }
            if (n2 < 0) {
                std::fprintf(stderr, "dispatch error (secondary): %s\n",
                             src2->lastError());
                return 1;
            }
        }
        // Answer any pending ARP (and future background-service input) inline on
        // this thread before stepping the SM — a tester-spoofed source IP the DUT
        // is resolving gets its Reply within this iteration's ~20 ms cadence.
        for (::tc8::IPollableService *svc : services) {
            svc->onReadable();
        }
        runner->tick();
        // Non-blocking pcap_dispatch (set in PcapSource::openLive) returns
        // immediately when no frames match — without this sleep we would
        // burn one CPU core spinning at ~10^7 ticks/sec. 20 ms cadence keeps
        // the SCXML scheduler responsive (deadline timers in seconds resolve
        // with 1% jitter at worst) without measurable CPU cost.
        if (n == 0 && n2 == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    // Post-verdict drain: keep the dumper writing for a bounded window
    // after the runner has verdicted so response packets which the
    // stimulus emits synchronously but the kernel ring delivers AFTER
    // the verdict-firing frame (e.g. OpQueryTcpEstablished UT response
    // in TCP_BASICS_02 / _07 / MSS_OPTIONS_01) still land in the saved
    // pcap. The runner is already frozen at the verdict-firing
    // transition — we deliberately do NOT call pipeline.processFrame()
    // or setNextPcapFrameIdx() during drain so the transition trace
    // stays the single source of truth and the drained frames simply
    // extend the pcap past the last trace-referenced index. Skipped on
    // signal-stop (user wants out) and on dispatch error (best-effort
    // here, verdict has already decided the run).
    constexpr int kPostVerdictDrainMs = 100;
    if (dumper != nullptr && !SignalGuard::stopRequested()) {
        const auto drain_deadline = std::chrono::steady_clock::now() +
                                    std::chrono::milliseconds(kPostVerdictDrainMs);
        while (std::chrono::steady_clock::now() < drain_deadline) {
            // Keep answering the DUT's ARP during the drain so its final Response
            // (which may need the spoofed source IP resolved) is emitted and lands
            // in the saved pcap.
            for (::tc8::IPollableService *svc : services) {
                svc->onReadable();
            }
            const int dn = src->dispatch(
                /*max_frames=*/-1,
                [&](const pcap_pkthdr &hdr, const u_char *data) {
                    pcap_dump(reinterpret_cast<u_char *>(dumper), &hdr, data);
                });
            int dn2 = 0;
            if (src2) {
                dn2 = src2->dispatch(
                    /*max_frames=*/-1,
                    [&](const pcap_pkthdr &hdr, const u_char *data) {
                        pcap_dump(reinterpret_cast<u_char *>(dumper), &hdr, data);
                    });
            }
            if (dn < 0 || dn2 < 0) {
                break;
            }
            if (dn == 0 && dn2 == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
        }
    }

    // If the run loop exited without the state machine reaching a final state,
    // the assertion was never concluded. Two distinct causes, two classes
    // (see docs/verdict_policy.md; ISO/IEC 9646 / TTCN-3):
    //   - interrupted (SIGINT/SIGTERM): the test system was stopped externally
    //     and did not run to completion — a test-system condition -> ERROR.
    //   - harness budget (-t) elapsed: for liveness-driven cases (e.g. a long
    //     throughput race whose SCXML runs as long as the wire stays live) the
    //     budget is the deliberate observation bound, so reaching it means the
    //     purpose could not be decided -> INCONCLUSIVE. Never a false FAIL: the
    //     DUT was not shown to violate anything.
    ::tc8::sce::Verdict verdict = runner->verdict();
    if (!runner->isDone()) {
        verdict = SignalGuard::stopRequested()
                      ? ::tc8::sce::Verdict{::tc8::sce::VerdictClass::Error, "interrupted"}
                      : ::tc8::sce::Verdict{::tc8::sce::VerdictClass::Inconclusive,
                                            "harness_budget_exceeded"};
    }
    const std::string verdict_str = verdict.str();
    std::printf("verdict  : %s\n", verdict_str.c_str());
    // Surface the witnessing evidence on any non-pass verdict so a
    // value-comparison failure (e.g. a timing-window flake like
    // dut_*_interval_out_of_range) is self-diagnosing in the conformance
    // gate without a pcap re-run. Reuses the Evidence-Export transition
    // trace (the single observation SSOT, frame_delta_us et al. carried in
    // each step's captured_json); a passing run needs no evidence and stays
    // quiet, keeping the gate output clean.
    if (verdict.cls != ::tc8::sce::VerdictClass::Pass) {
        std::printf("evidence : %s\n", runner->dumpTraceJson().c_str());
    }
    if (dumper != nullptr) {
        pcap_dump_close(dumper);
    }

    // Evidence Export (Option 3) — emit the transition trace alongside the
    // pcap so decode_pcap.py can merge it into the per-case JSON. The
    // sidecar path is the pcap path with ``.pcap`` replaced by
    // ``.trace.json`` (or ``<pcap>.trace.json`` when there's no .pcap
    // suffix). Skipped silently when --pcap-dump wasn't requested — a
    // run without a retained pcap has no frame-idx correlation anchor,
    // so the walker has no use for the trace. NOTE: this exports only the
    // verdict-trace events; the site still re-decodes every frame in Python
    // (decode_pcap.py). Making this the FULL per-packet export would let the
    // site drop its decoder — see docs/tech-debt.md TD-05.
    if (!pcap_dump_path_.empty()) {
        std::string trace_path = pcap_dump_path_;
        const auto suffix_pos = trace_path.rfind(".pcap");
        if (suffix_pos != std::string::npos &&
            suffix_pos == trace_path.size() - 5) {
            trace_path.replace(suffix_pos, 5, ".trace.json");
        } else {
            trace_path.append(".trace.json");
        }
        const std::string trace_json = runner->dumpTraceJson();
        if (FILE *fp = std::fopen(trace_path.c_str(), "wb")) {
            std::fwrite(trace_json.data(), 1, trace_json.size(), fp);
            std::fclose(fp);
        } else {
            std::fprintf(stderr,
                         "warning: failed to write trace JSON to '%s'\n",
                         trace_path.c_str());
        }
    }

    // Process exit class (ISO/IEC 9646 / TTCN-3 model) so the smoke harness
    // and CI can tell a real DUT FAIL apart from a run that did not conclude.
    // The class->code mapping is the single one defined in verdict.h.
    return verdict.exitCode();
}

}  // namespace tc8::cli
