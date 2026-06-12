#include "cli/test_command.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <pcap/pcap.h>

#include "tc8/captured_event.h"

#include "capture/bpf_filter.h"
#include "capture/pcap_source.h"
#include "cli/expect_parser.h"
#include "cli/signal_handler.h"
#include "dissect/packet_pipeline.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/spec_inventory.h"
#include "sce_integration/test_config.h"

namespace tc8::cli {

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
    sub_->add_option("--inventory", inventory_path_,
                     "Path to spec inventory JSON "
                     "(default: docs/spec/case_inventory.json)");
    sub_->add_option("--inventory-overrides", overrides_path_,
                     "Path to inventory overrides JSON "
                     "(default: docs/spec/inventory_overrides.json)");
    sub_->add_option("--expect", expect_tokens_,
                     "DUT-specific expected values as KEY=VALUE tokens (repeatable). "
                     "SOME/IP keys (bare): service_id, instance_id, major_version, "
                     "ttl, minor_version, eventgroup_id (hex/decimal). "
                     "ARP keys (arp.* prefix): arp.dut_iface_ip, arp.tester_ip "
                     "(IPv4 dotted), arp.dut_iface_mac (six colon-separated hex "
                     "octets). Example: --expect service_id=0xF4E7 "
                     "arp.tester_ip=172.16.0.1 arp.dut_iface_mac=aa:bb:cc:dd:ee:ff");
    sub_->add_option("--stimulus-wait", stimulus_wait_ms_,
                     "Milliseconds to wait before the first tester-side stimulus "
                     "emit (default 1500, suits tc8-dut). Widen when the DUT's "
                     "SD initial_delay exceeds ~1s.");
    sub_->add_option("--stimulus-retry", stimulus_retry_ms_,
                     "Milliseconds between consecutive stimulus emits (default 1000).");
    sub_->add_option("--stimulus-emits", stimulus_emits_,
                     "Total stimulus datagrams sent during the boot sequence "
                     "(default 2). Higher counts cost wall time but tolerate jitter.");
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
    // Optional override-set lookup — loaded when either filter flag is
    // set. Failure to load surfaces with stderr + non-zero exit so
    // smoke/CI invocations don't silently fall back to the full list.
    std::optional<sce::SpecInventory> inv_for_filter;
    if (exclude_deferred_ || exclude_platform_known_fail_) {
        const std::string inv_path = inventory_path_.empty()
            ? std::string("docs/spec/case_inventory.json")
            : inventory_path_;
        const std::string ov_path = overrides_path_.empty()
            ? std::string("docs/spec/inventory_overrides.json")
            : overrides_path_;
        std::string err;
        inv_for_filter = sce::SpecInventory::load(inv_path, ov_path, &err);
        if (!inv_for_filter.has_value()) {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 2;
        }
    }

    const auto entries = sce::CaseRegistry::instance().listSorted(list_all_);
    std::string_view current_category;
    std::size_t emitted = 0;
    for (const auto *e : entries) {
        if (inv_for_filter.has_value()) {
            const auto canon = sce::SpecInventory::canonicalise(std::string{e->id});
            if (const auto *sc = inv_for_filter->find(canon); sc != nullptr) {
                if (exclude_deferred_ && !sc->expected) {
                    continue;
                }
                if (exclude_platform_known_fail_ && sc->platform_known_fail) {
                    continue;
                }
            }
        }
        if (e->category != current_category) {
            if (!current_category.empty()) {
                std::puts("");
            }
            std::printf("%.*s\n", static_cast<int>(e->category.size()), e->category.data());
            current_category = e->category;
        }
        const char *tag = e->deprecated ? " [deprecated]" : "";
        std::printf("  %-28.*s  §%-10.*s %.*s%s\n", static_cast<int>(e->id.size()), e->id.data(),
                    static_cast<int>(e->spec_section.size()), e->spec_section.data(),
                    static_cast<int>(e->description.size()), e->description.data(), tag);
        ++emitted;
    }
    if (exclude_deferred_ || exclude_platform_known_fail_) {
        std::string note;
        if (exclude_deferred_) {
            note = "deferred";
        }
        if (exclude_platform_known_fail_) {
            note += note.empty() ? "" : "+";
            note += "platform_known_fail";
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
    auto inv_opt = sce::SpecInventory::load(inv_path, ov_path, &err);
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

    const auto *entry = sce::CaseRegistry::instance().find(case_id_);
    if (entry == nullptr) {
        std::fprintf(stderr, "error: unknown case '%s' (try --list-cases)\n", case_id_.c_str());
        return 2;
    }
    if (entry->deprecated) {
        std::fprintf(stderr, "error: case '%s' is marked deprecated in the spec\n", case_id_.c_str());
        return 2;
    }

    const std::string bpf = bpf_override.has_value() ? *bpf_override : capture::bpf::expressionFor(entry->bpf_group);

    std::printf("case     : %.*s  (§%.*s)\n", static_cast<int>(entry->id.size()), entry->id.data(),
                static_cast<int>(entry->spec_section.size()), entry->spec_section.data());
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

    std::unique_ptr<sce::ITestRunner> runner = entry->factory(config);
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
    runner->kickStimulus(iface_);

    // Initialize the state machine AFTER stimulus so SCXML delay-based
    // deadline timers arm fresh. Without this split the stimulus's wall
    // time would count against the listen window.
    runner->start();

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

    const auto verdict = runner->verdict();
    std::printf("verdict  : %.*s\n", static_cast<int>(verdict.size()), verdict.data());
    if (dumper != nullptr) {
        pcap_dump_close(dumper);
    }

    // Evidence Export (Option 3) — emit the transition trace alongside the
    // pcap so decode_pcap.py can merge it into the per-case JSON. The
    // sidecar path is the pcap path with ``.pcap`` replaced by
    // ``.trace.json`` (or ``<pcap>.trace.json`` when there's no .pcap
    // suffix). Skipped silently when --pcap-dump wasn't requested — a
    // run without a retained pcap has no frame-idx correlation anchor,
    // so the walker has no use for the trace.
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

    return verdict == "pass" ? 0 : 1;
}

}  // namespace tc8::cli
