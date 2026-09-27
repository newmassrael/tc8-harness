#include "cli/test_command.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <poll.h>

#include <pcap/pcap.h>

#include "tc8/capture_stats.h"
#include "tc8/dut_ready_signal.h"  // the --go-file contract (start-order barrier)
#include "tc8/unperformed_stimulus.h"
#include "tc8/captured_event.h"
#include "tc8/pollable_service.h"

#include "capture/bpf_filter.h"
#include "capture/multicast_membership.h"
#include "capture/pcap_source.h"
#include "tc8/dut_config.h"  // kSdMcastGroup — the SD group's compiled-in default
#include "tc8/net/link_control.h"  // captureSnaplenFor
#include "cli/expect_parser.h"
#include "cli/signal_handler.h"
#include "dissect/packet_pipeline.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/case_spec.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/dut_control_factory.h"
#include "sce_integration/spec_coverage.h"
#include "sce_integration/spec_inventory.h"
#include "sce_integration/test_config.h"
#include "sce_integration/verdict.h"

namespace tc8::cli {

namespace {

// --- The DUT-ready half of the start-order barrier (--go-file) ---------------
//
// `--ready-file` is one-directional: it tells a launcher "you may start the DUT
// now" and this process then walks straight on to `kickStimulus`, never learning
// that the DUT did start. A case whose stimulus is fire-and-forget — a datagram
// with no retry and no solicited response to re-drive it — loses that race
// whenever the DUT is the slower of the two, and NOTHING reports it: the datagram
// is on the wire, the case simply observes nothing. Measured on a two-machine
// wire: three On-Event CAN triggers all answered by the DUT host's kernel with
// ICMP port-unreachable (`Udp: NoPorts` +3, time-aligned), the last of them
// missing the DUT's bind of its receive port by 147 ms.
//
// `--go-file` is the mirror the launcher creates once it has finished deciding
// whether the DUT came up (the orchestrator polls the DUT log for the DUT's own
// readiness announcement), and this is the WAIT for it — placed before
// `makeDutControl` so it also covers the DUT-control capability query, which is
// itself a UT round trip that a not-yet-listening DUT would fail.
//
// The signal's three states, and why its content and not merely its presence
// carries the answer, are the contract in `tc8/dut_ready_signal.h` — which owns
// the reading so that contract has one tested home. Only the waiting is here.
//
// Reaching the ceiling below means something narrower than "no DUT": the launcher
// itself died or never intended to signal, since a launcher that decided "not
// bound" says so in milliseconds. It is set ABOVE the launcher's own DUT-ready
// ceiling (dispatch.rs `DUT_READY_POLL_MS` × `DUT_READY_MAX_POLLS` = 10 s) so the
// launcher is always the party that gets to decide first.
constexpr int kGoFilePollMs = 20;
constexpr int kGoFileMaxPolls = 750;  // 15 s = the launcher's 10 s + 5 s of grace

/// The name recorded in `tc8::UnperformedStimulus` when the barrier is not
/// honoured. It reaches a report as `inconclusive:stimulus_<name>_not_performed`.
constexpr const char *kDutReadyBarrierStimulus = "dut_ready_barrier";

/// Block until the launcher signals what happened to the DUT, then let the caller
/// proceed. Returns whether the DUT was proven bound.
///
/// The case still RUNS when it was not — the pcap and the logs are the evidence an
/// operator needs, and refusing to run would destroy them — but the run is marked
/// as one whose stimulus could not be performed. That is not bookkeeping: for a
/// case asserting an ABSENCE, a stimulus the DUT never received produces silence,
/// and silence is the pass condition, so without this the case would report a
/// confident PASS having tested nothing. Measured: with the DUT replaced by a
/// binary that exits immediately, ICMPv4_TYPE_08 reported `pass`. The ledger's
/// verdict-site guard turns it into a non-conclusion instead, overriding pass and
/// fail alike.
bool waitForDutReady(const std::string &go_file) {
    for (int i = 0; i < kGoFileMaxPolls; ++i) {
        const ::tc8::DutReadyReport signal = ::tc8::readDutReadySignal(go_file);
        if (signal.state == ::tc8::DutReadyState::Bound) {
            return true;
        }
        if (signal.state == ::tc8::DutReadyState::NotBound) {
            std::fprintf(stderr,
                         "warning: the launcher could not prove the DUT was listening: %s. "
                         "The stimulus is sent anyway so the capture and logs survive, but "
                         "this run cannot conclude about the DUT.\n",
                         signal.reason.c_str());
            ::tc8::UnperformedStimulus::record(kDutReadyBarrierStimulus);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kGoFilePollMs));
    }
    std::fprintf(stderr,
                 "warning: the --go-file DUT-ready signal '%s' did not arrive within "
                 "%d ms — the launcher never decided. The stimulus is sent WITHOUT the "
                 "DUT having been proven bound, so this run cannot conclude about the "
                 "DUT.\n",
                 go_file.c_str(), kGoFilePollMs * kGoFileMaxPolls);
    ::tc8::UnperformedStimulus::record(kDutReadyBarrierStimulus);
    return false;
}

// Resolve a case's spec section from the loaded inventory — the SSOT
// (docs/spec/case_inventory.json, mined from the TC8 spec PDF). The
// harness deliberately does NOT store a per-case section copy in the
// case traits: a hand-authored copy drifts from the spec (cf.
// case_registry.h, where `category` is likewise derived, not stored).
// Returns "-" when the inventory is unavailable or the id is out-of-spec
// (e.g. an OEM case shipped without an extra inventory JSON).
// The single "section or '-'" fallback policy, shared by both display paths
// (runCase and the runListCases loop, each of which already holds the SpecCase
// specCaseFor resolved for it).
std::string sectionOf(const sce::SpecCase *sc) {
    return (sc != nullptr && !sc->section.empty()) ? sc->section : std::string{"-"};
}

// The inventory's entries for a registered case — `own` for the section and the
// verdict-excusing axes, `execution` for everything that decides what runs — or
// both nullptr when the inventory is unavailable, the same best-effort contract
// sectionOf's "-" fallback encodes, so every consumer shares one lookup. The two
// differ only for an alias; which axis reads which is case_spec.h's to decide,
// and every reader below takes the view that header assigns its axis.
sce::CaseSpec specCaseFor(const std::optional<sce::SpecInventory> &inv,
                          const sce::CaseEntry &entry) {
    if (!inv.has_value()) {
        return {};
    }
    return sce::resolveCaseSpec(*inv, entry);
}

// The display suffix naming an alias's target and the target's current execution
// surface, or "" for an authored case. When the pointer file pinned a surface that
// no longer matches, the suffix says so — the report half of question 4 of the
// alias design: drift is shown where the alias is listed, never refused.
std::string aliasTag(const sce::CaseEntry &entry, const sce::CaseSpec &spec) {
    if (!entry.isAlias()) {
        return {};
    }
    const std::string now = sce::executionSurface(entry, spec);
    std::string tag =
        " [alias of " + sce::qualifiedCaseId(entry.alias_of.suite, entry.alias_of.id);
    if (entry.alias_surface_pin.empty() || entry.alias_surface_pin == now) {
        tag += ", surface " + now + "]";
    } else {
        tag += ", surface CHANGED: pinned " + std::string{entry.alias_surface_pin} + ", now " +
               now + "]";
    }
    return tag;
}

// Whether a negative-row flip leaves the driver's own base value for its key
// unchanged, so the "wrong" value is the deployment's actual one and the flip is
// not a flip. `neg_wrong_token` is an ABSOLUTE bogus value whose wrongness is a
// property of the reference deployment; a case run under any other deployment —
// an alias always is — can meet a site that genuinely uses it. The run would then
// pass and be mapped to a Fail blaming the DUT, so this refuses it up front and
// names the collision instead. Compared on the key and the value's spelling,
// case-insensitively (MAC and hex values vary in case); a value the driver spells
// differently but means the same is not caught, and fails loudly as before.
bool flipIsNoOp(const std::string &flip, const std::vector<std::string> &base_tokens) {
    const auto eq = flip.find('=');
    if (eq == std::string::npos) {
        return false;
    }
    const std::string_view key{flip.data(), eq + 1};  // "key=" — the '=' anchors it
    const auto lower = [](std::string_view s) {
        std::string out{s};
        std::transform(out.begin(), out.end(), out.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    };
    // Last wins among the driver's tokens, exactly as applyExpectToken applies them.
    for (auto it = base_tokens.rbegin(); it != base_tokens.rend(); ++it) {
        if (std::string_view{*it}.substr(0, key.size()) == key) {
            return lower(std::string_view{*it}.substr(key.size())) ==
                   lower(std::string_view{flip}.substr(key.size()));
        }
    }
    return false;
}

}  // namespace

TestCommand::TestCommand(CLI::App &app) {
    sub_ = app.add_subcommand("test", "Run a registered TC8 test case against a live NIC");

    sub_->add_option("-c,--case", case_id_, "Case ID to run (see --list-cases)");
    sub_->add_option("--suite", suite_,
                     "Case catalog to scope to. With --list-cases, --list-neg-rows "
                     "or --list-vsomeip-variants: only that suite (default: every "
                     "suite, non-default ones printed as suite:ID). With --vs-spec: "
                     "the one suite whose registered cases are measured against "
                     "its own inventory (default: the in-tree suite). With --case: "
                     "resolve an unqualified id within that suite.");
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
    sub_->add_flag("--list-neg-rows", list_neg_rows_,
                   "Print every case carrying an authored negative row as "
                   "CASE|wrong_token|fail:reason (the grammar smoke-test.sh's "
                   "NEG_ROWS array used) and exit. A driver iterates this to "
                   "know which cases to run with --negative-row and which "
                   "verdict to assert; --negative-row injects the token itself, "
                   "so the driver never re-emits it.");
    sub_->add_flag("--list-known-fails", list_known_fails_,
                   "Print every platform known-fail carrying a MEASURED landed "
                   "verdict as CASE|class:reason and exit. A driver iterates this, "
                   "runs each case with NOTHING injected (the platform's own "
                   "deviation produces the verdict) and asserts it — the answer to "
                   "--exclude-platform-known-fail meaning neither lane ever "
                   "re-measures these registrations. An entry with no measured "
                   "verdict is omitted, not an error.");
    sub_->add_flag("--list-vsomeip-variants", list_vsomeip_variants_,
                   "Print every case whose overrides declare a DUT vsomeip flavor "
                   "(the seventh inventory-overrides axis) as CASE|cfg|env1,env2 and "
                   "exit — cfg is an alternate vsomeip config basename (empty = keep "
                   "the base) and env are TC8_DUT_* the DUT app reads; a declaration "
                   "with both empty prints CASE|| (the base DUT, declared). The harness never "
                   "launches the DUT; a driver iterates this to spawn it with the "
                   "right flavor.");
    sub_->add_flag("--negative-row", negative_row_,
                   "Run the case with its authored expectation flip applied — "
                   "the self-check that its guard is not trivially-true. The "
                   "flip and its expected fail verdict are the inventory "
                   "overrides' sixth axis, and neg_expect_overrides replaces the "
                   "positive expect_overrides. Errors if the case has no "
                   "authored row. Unrelated to a _NEG-suffixed case, which is a "
                   "separately registered firmware-mutant case.");
    sub_->add_option("--negative-row-index", negative_row_index_,
                     "Which of the case's authored rows --negative-row runs "
                     "(default 0, the primary). A case whose SCXML has more than "
                     "one expectation-graded fail final authors one row each, and "
                     "--list-neg-rows prints the index to pass here.");
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
    sub_->add_option("--ready-file", ready_file_path_,
                     "Create this file once the live capture is armed and its "
                     "multicast memberships are held (before any DUT-driving "
                     "stimulus), so a launcher can start the DUT only after the "
                     "capture can observe its first frame. Empty = disabled.");
    sub_->add_option("--go-file", go_file_path_,
                     "Wait for this file before sending any stimulus. The mirror of "
                     "--ready-file: the launcher creates it once it has decided "
                     "whether the DUT bound its receive ports — empty means it did, "
                     "non-empty is the reason it could not be shown — so a "
                     "fire-and-forget stimulus is never emitted at a DUT that is not "
                     "listening yet. When the DUT was not proven bound the case still "
                     "runs, but its stimulus is recorded as unperformed and the "
                     "verdict is a non-conclusion rather than a pass it cannot "
                     "support. Empty = disabled.");
    sub_->add_flag("!--no-multicast-membership", multicast_membership_,
                   "Do not hold IGMP memberships for the multicast groups this "
                   "case observes. The default (hold them) is what lets an "
                   "absence-based verdict mean anything on a wire that prunes "
                   "unjoined groups. Decline it only on a wire that forwards "
                   "multicast unconditionally AND where the tester must emit no "
                   "IGMP of its own — an absence-asserting case then reports "
                   "inconclusive rather than a pass it cannot support.");
}

std::optional<sce::SpecInventory> TestCommand::loadInventory(std::string *err,
                                                            bool *stripped) const {
    static constexpr const char *kDefaultInventory = "docs/spec/case_inventory.json";
    static constexpr const char *kDefaultOverrides = "docs/spec/inventory_overrides.json";
    std::error_code ec;
    const bool inventory_given = !inventory_path_.empty();
    const std::string inv_path = inventory_given ? inventory_path_ : kDefaultInventory;
    *stripped = !inventory_given && !std::filesystem::exists(inv_path, ec);
    // A GIVEN overrides path goes to the loader as is, which refuses one it cannot
    // open. The DEFAULT one is passed only when it exists: its absence means "this
    // platform has no overrides", the one absence that is not a mistake.
    std::string ov_path = overrides_path_;
    if (ov_path.empty() && std::filesystem::exists(kDefaultOverrides, ec)) {
        ov_path = kDefaultOverrides;
    }
    auto inv = sce::SpecInventory::load(inv_path, inventory_extra_paths_, ov_path, err);
    if (!inv.has_value()) {
        return inv;
    }
    // Checked here, the one funnel every inventory reader goes through, so no path
    // can resolve an alias whose own entry claims an axis that will be ignored.
    const auto conflicts = sce::aliasAxisConflicts(*inv, sce::CaseRegistry::instance());
    if (!conflicts.empty()) {
        *err = conflicts.front();
        for (std::size_t i = 1; i < conflicts.size(); ++i) {
            *err += "\n       " + conflicts[i];
        }
        return std::nullopt;
    }
    return inv;
}

// Emits the authored negative rows in the historical NEG_ROWS grammar
// (`CASE|wrong_token|fail:reason`), sorted by case id so a driver's iteration
// order — and any diff of this output — is stable. This is the surface that
// replaces the bash array for BOTH drivers and for
// tools/negative_coverage_audit.py's SOUND_ROW disposition.
int TestCommand::runListNegRows() const {
    std::string err;
    bool stripped = false;
    const auto inv = loadInventory(&err, &stripped);
    if (!inv.has_value()) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }
    if (!suite_.empty() && !inv->hasSuite(suite_)) {
        std::fprintf(stderr, "error: --suite %s: no inventory declares that suite\n",
                     suite_.c_str());
        return 1;
    }
    std::vector<std::string> rows;
    // `CASE|INDEX|token|verdict`. The INDEX is what `--negative-row` takes: a case
    // may author more than one row (a template with two expectation-graded fail
    // finals needs one each), and without it the driver could name the case but
    // not which of its rows to run.
    const auto emit = [&rows](const std::string &qid, const sce::SpecCase &sc) {
        if (sc.neg_wrong_token.empty()) {
            return;
        }
        rows.push_back(qid + "|0|" + sc.neg_wrong_token + "|" + sc.neg_expect_fail);
        for (std::size_t i = 0; i < sc.neg_extra_wrong_tokens.size(); ++i) {
            rows.push_back(qid + "|" + std::to_string(i + 1) + "|" +
                           sc.neg_extra_wrong_tokens[i] + "|" + sc.neg_extra_expect_fails[i]);
        }
    };
    for (const auto &sc : inv->cases()) {
        if (inSuiteScope(sc.suite)) {
            emit(sce::qualifiedCaseId(sc.suite, sc.id), sc);
        }
    }
    // An alias runs its target's rows under its own id (case_spec.h): the
    // self-check belongs to the case, and the alias IS the case. Its own entry can
    // declare none — loadInventory refused that — so no id is listed twice.
    for (const auto *e : sce::CaseRegistry::instance().listSorted(/*include_deprecated=*/true)) {
        if (!e->isAlias() || !inSuiteScope(e->suite)) {
            continue;
        }
        if (const sce::SpecCase *target = sce::resolveCaseSpec(*inv, *e).execution) {
            emit(sce::qualifiedCaseId(e->suite, e->id), *target);
        }
    }
    std::sort(rows.begin(), rows.end());
    for (const auto &r : rows) {
        std::printf("%s\n", r.c_str());
    }
    return 0;
}

// Emits the platform known-fails that have a MEASURED landed verdict, as
// `CASE|class:reason`, sorted for a stable iteration order and diff. The sibling of
// runListNegRows above, and deliberately the same grammar minus the flip column: a
// negative row needs an injected wrong value to reach its verdict, while a known-fail
// needs nothing injected at all — the platform's own deviation produces it.
//
// This exists because `--exclude-platform-known-fail` means both lanes SKIP these cases,
// so nothing re-measures the registration and a stale one is invisible: a platform that
// was fixed, or whose defect changed shape, keeps its entry and keeps being skipped for
// it. A driver iterates this, runs each case with nothing injected, and asserts the
// verdict — the same shape that keeps the sixth axis honest.
//
// An entry with no measured verdict is OMITTED rather than reported as an error: a
// deviation may be registered before anyone has run it, and a listing that refused to
// print would make adding the first entry impossible.
int TestCommand::runListKnownFails() const {
    std::string err;
    bool stripped = false;
    const auto inv = loadInventory(&err, &stripped);
    if (!inv.has_value()) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }
    if (!suite_.empty() && !inv->hasSuite(suite_)) {
        std::fprintf(stderr, "error: --suite %s: no inventory declares that suite\n",
                     suite_.c_str());
        return 1;
    }
    std::vector<std::string> rows;
    for (const auto &sc : inv->cases()) {
        if (!inSuiteScope(sc.suite)) {
            continue;
        }
        if (sc.platform_known_fail && !sc.platform_known_fail_verdict.empty()) {
            rows.push_back(sce::qualifiedCaseId(sc.suite, sc.id) + "|" +
                           sc.platform_known_fail_verdict);
        }
    }
    std::sort(rows.begin(), rows.end());
    for (const auto &r : rows) {
        std::printf("%s\n", r.c_str());
    }
    return 0;
}

// The seventh axis (vsomeip_cfg / vsomeip_env) as CASE|cfg|env1,env2 lines — the
// harness's exposer for a driver-launched DUT flavor, mirroring runListNegRows.
// Both smoke-test.sh and the orchestrator read this ONE source, so the flavor
// table cannot drift across the two drivers.
int TestCommand::runListVsomeipVariants() const {
    std::string err;
    bool stripped = false;
    const auto inv = loadInventory(&err, &stripped);
    if (!inv.has_value()) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }
    if (!suite_.empty() && !inv->hasSuite(suite_)) {
        std::fprintf(stderr, "error: --suite %s: no inventory declares that suite\n",
                     suite_.c_str());
        return 1;
    }
    std::vector<std::string> rows;
    // `flavor` null = the base DUT: cfg and env both empty.
    const auto emit = [&rows](const std::string &qid, const sce::SpecCase *flavor) {
        std::string cfg;
        std::string env;
        if (flavor != nullptr) {
            cfg = flavor->vsomeip_cfg;
            for (std::size_t i = 0; i < flavor->vsomeip_env.size(); ++i) {
                env += (i != 0 ? "," : "") + flavor->vsomeip_env[i];
            }
        }
        rows.push_back(qid + "|" + cfg + "|" + env);
    };
    for (const auto &sc : inv->cases()) {
        // A row per DECLARATION, not per non-empty value: `ID||` is a case that
        // declared the base DUT, which the orchestrator must be able to tell from a
        // case that declared nothing (spec_inventory.h, vsomeip_declared).
        if (inSuiteScope(sc.suite) && sc.vsomeip_declared) {
            emit(sce::qualifiedCaseId(sc.suite, sc.id), &sc);
        }
    }
    // An alias ALWAYS declares: its DUT is its target's, which is the target's
    // flavor when it has one and the base DUT when it does not. Leaving the base
    // case unlisted would let the orchestrator refuse an alias whose id happens to
    // spell an in-tree case that does carry a flavor — the refusal meant for a case
    // whose DUT cannot be known, when this one's is known exactly.
    for (const auto *e : sce::CaseRegistry::instance().listSorted(/*include_deprecated=*/true)) {
        if (!e->isAlias() || !inSuiteScope(e->suite)) {
            continue;
        }
        const sce::SpecCase *target = sce::resolveCaseSpec(*inv, *e).execution;
        emit(sce::qualifiedCaseId(e->suite, e->id),
             (target != nullptr && target->vsomeip_declared) ? target : nullptr);
    }
    std::sort(rows.begin(), rows.end());
    for (const auto &r : rows) {
        std::printf("%s\n", r.c_str());
    }
    return 0;
}

bool TestCommand::inSuiteScope(std::string_view suite) const {
    return suite_.empty() || sce::canonicalSuite(suite) == sce::canonicalSuite(suite_);
}

int TestCommand::run(std::optional<std::string> bpf_override) {
    if (!suite_.empty() && !sce::isWellFormedSuite(suite_)) {
        std::fprintf(stderr,
                     "error: --suite '%s' is not a valid suite name ([A-Za-z_][A-Za-z0-9_]*)\n",
                     suite_.c_str());
        return 2;
    }
    if (list_vsomeip_variants_) {
        return runListVsomeipVariants();
    }
    if (list_neg_rows_) {
        return runListNegRows();
    }
    if (list_known_fails_) {
        return runListKnownFails();
    }
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
    std::string err;
    bool stripped = false;
    std::optional<sce::SpecInventory> inv = loadInventory(&err, &stripped);
    if (!inv.has_value()) {
        // The filter flags REQUIRE the inventory — fail loudly so smoke/CI
        // invocations never silently fall back to an unfiltered list. So does
        // any failure other than a missing DEFAULT inventory: a file the caller
        // named, or one that exists and does not parse, is a mistake to report.
        if (need_filter || !stripped) {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 2;
        }
        // No filters requested and no inventory in this tree: the section column
        // degrades to "-" but the registered list stays useful.
        std::fprintf(stderr, "warning: %s (spec sections shown as '-')\n", err.c_str());
    }

    const auto entries = sce::CaseRegistry::instance().listSorted(list_all_);
    // A scope that matches nothing would print an empty list, and a CI lane
    // built from that runs ZERO cases green — the same vacuity --only-serial's
    // exclusion guards against. Refuse it.
    if (!suite_.empty() &&
        std::none_of(entries.begin(), entries.end(),
                     [this](const sce::CaseEntry *e) { return inSuiteScope(e->suite); })) {
        std::fprintf(stderr, "error: --suite %s: no registered case belongs to that suite\n",
                     suite_.c_str());
        return 2;
    }
    std::string_view current_suite;
    std::string_view current_category;
    std::size_t emitted = 0;
    for (const auto *e : entries) {
        if (!inSuiteScope(e->suite)) {
            continue;
        }
        const sce::CaseSpec spec = specCaseFor(inv, *e);
        if (need_filter) {
            // Lane routing is an execution axis (the target's, for an alias);
            // deferral and known-fail are the case's own (case_spec.h).
            const sce::SpecCase *exec = spec.execution;
            const sce::SpecCase *own = spec.own;
            // timing_serial defaults false, so a case with no override entry is
            // non-serial — --only-serial drops it, --exclude-serial keeps it.
            const bool serial = (exec != nullptr) && exec->timing_serial;
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
                (exec != nullptr) && exec->requires_secondary_iface;
            if (only_secondary_iface_ && !secondary_iface) {
                continue;
            }
            if (own != nullptr) {
                if (exclude_deferred_ && !own->expected) {
                    continue;
                }
                if (exclude_platform_known_fail_ && own->platform_known_fail) {
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
        const std::string section = sectionOf(spec.own);
        const char *tag = e->deprecated ? " [deprecated]" : "";
        // Non-default suites print the qualified "suite:id" so the listed token
        // is the exact `--case` arg to run it; the in-tree suite stays bare
        // (output byte-identical to before any suite injection).
        const std::string display_id = sce::qualifiedCaseId(e->suite, e->id);
        const std::string alias = aliasTag(*e, spec);
        std::printf("  %-28.*s  §%-10.*s %.*s%s%s\n",
                    static_cast<int>(display_id.size()), display_id.data(),
                    static_cast<int>(section.size()), section.data(),
                    static_cast<int>(e->description.size()), e->description.data(), tag,
                    alias.c_str());
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
    } else if (!suite_.empty()) {
        // Counted like the unscoped total below: every registered case of the
        // suite, deprecated ones included.
        const auto all = sce::CaseRegistry::instance().listSorted(/*include_deprecated=*/true);
        const auto n = std::count_if(all.begin(), all.end(), [this](const sce::CaseEntry *e) {
            return inSuiteScope(e->suite);
        });
        std::printf("\n%zu case(s) registered in suite %s.\n", static_cast<std::size_t>(n),
                    sce::canonicalSuite(suite_).c_str());
    } else {
        std::printf("\n%zu case(s) registered.\n", sce::CaseRegistry::instance().size());
    }
    return 0;
}

int TestCommand::runVsSpecReport() const {
    std::string err;
    bool stripped = false;
    const auto inv_opt = loadInventory(&err, &stripped);
    if (!inv_opt.has_value()) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 2;
    }
    // One catalog per report. Counting every suite's registered ids against the
    // TC8 inventory let an injected suite's same-id case mark the TC8 spec case
    // registered, so the CI gate (--vs-spec --strict) could pass on a case the
    // TC8 catalog does not register. Unscoped means the in-tree suite: that is
    // the catalog the gate exists for.
    const std::string_view scope = suite_.empty() ? sce::kDefaultSuite : std::string_view{suite_};
    const auto coverage_opt =
        sce::computeSpecCoverage(sce::CaseRegistry::instance(), *inv_opt, scope);
    if (!coverage_opt.has_value()) {
        std::fprintf(stderr,
                     "error: --vs-spec --suite %.*s: no inventory declares that suite "
                     "(pass its catalog with --inventory-extra; the file's root \"suite\" "
                     "names it)\n",
                     static_cast<int>(scope.size()), scope.data());
        return 2;
    }
    const auto &coverage = *coverage_opt;
    // The in-tree report stays byte-identical; any other suite's is labelled,
    // as --list-cases labels it.
    if (!sce::isDefaultSuite(scope)) {
        std::printf("== suite: %s ==\n", sce::canonicalSuite(scope).c_str());
    }

    int total_expected = 0;
    int total_registered = 0;
    int total_missing = 0;
    int total_deferred = 0;
    for (const auto &row : coverage.categories) {
        const std::string &cat = row.name;
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
    if (!coverage.registered_only.empty()) {
        std::printf("\nregistered-but-not-in-spec (harness-only) : %zu\n",
                    coverage.registered_only.size());
        for (const auto &id : coverage.registered_only) {
            std::printf("  - %s\n", id.c_str());
        }
    }

    const double coverage_pct = total_expected == 0
        ? 0.0
        : 100.0 * static_cast<double>(total_registered) / static_cast<double>(total_expected);
    std::printf("\nSummary: %d / %d expected (%.1f%% coverage); missing=%d, deferred=%d\n",
                total_registered, total_expected, coverage_pct, total_missing, total_deferred);

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
    // --suite supplies the qualifier instead; the two must not disagree.
    const sce::CaseEntry *entry = nullptr;
    const sce::QualifiedCaseId qid = sce::splitQualifiedCaseId(case_id_);
    if (!qid.suite.empty() && !suite_.empty() && !inSuiteScope(qid.suite)) {
        std::fprintf(stderr, "error: --case %s names a different suite than --suite %s\n",
                     case_id_.c_str(), suite_.c_str());
        return 2;
    }
    if (!qid.suite.empty()) {
        entry = sce::CaseRegistry::instance().find(qid.suite, qid.id);
    } else if (!suite_.empty()) {
        entry = sce::CaseRegistry::instance().find(suite_, qid.id);
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
    std::string inv_err;
    bool stripped = false;
    const auto inv = loadInventory(&inv_err, &stripped);
    // A run with no inventory in the tree still runs (its section shows "-"),
    // since there are no per-case axes to lose. Any other failure — a file the
    // caller named, or one that does not parse — would silently run the case
    // without its stimulus overrides, negative row and routing, so it stops here.
    if (!inv.has_value() && !stripped) {
        std::fprintf(stderr, "error: %s\n", inv_err.c_str());
        return 2;
    }
    // Resolved once. The section comes from the case's own catalog entry; the
    // stimulus overrides and the negative row further down are execution axes,
    // which for an alias are its target's (case_spec.h).
    const sce::CaseSpec spec = specCaseFor(inv, *entry);
    const sce::SpecCase *sc = spec.execution;
    const std::string section = sectionOf(spec.own);

    std::printf("case     : %.*s  (§%s)\n", static_cast<int>(entry->id.size()), entry->id.data(),
                section.c_str());
    // Provenance, printed on every alias run: the verdict below is produced by the
    // target's state machine and, under --negative-row, proven by the target's
    // authored flip, so the alias's row must be able to cite whose they were.
    if (entry->isAlias()) {
        const std::string now = sce::executionSurface(*entry, spec);
        std::printf("alias_of : %s (surface %s)\n",
                    sce::qualifiedCaseId(entry->alias_of.suite, entry->alias_of.id).c_str(),
                    now.c_str());
        // Reported, not refused: the run goes ahead and its verdict stands for
        // what ran, but whoever reads the row learns the target moved since the
        // alias was last reviewed.
        if (!entry->alias_surface_pin.empty() && entry->alias_surface_pin != now) {
            std::fprintf(stderr,
                         "warning: alias target surface changed since it was pinned "
                         "(pinned %.*s, now %s); review the target's traits and inventory "
                         "axes, then update the pointer file's `surface` line\n",
                         static_cast<int>(entry->alias_surface_pin.size()),
                         entry->alias_surface_pin.data(), now.c_str());
        }
    }
    std::printf("source   : test live (%s)\n", iface_.c_str());
    std::printf("bpf      : %s\n", bpf.c_str());

    // Snaplen from the link's own MTU, not a blanket 65535 — see
    // tc8::net::captureSnaplenFor: immediate mode forces TPACKET_V2's fixed
    // snaplen-sized ring slots, so 65535 shrinks a 16 MB ring to ~256 frames.
    // 65535 stays the fallback for an unreadable MTU (never assume "small").
    const unsigned snaplen = ::tc8::net::captureSnaplenFor(iface_, 65535);
    std::printf("snaplen  : %u (iface mtu %u)\n", snaplen, ::tc8::net::linkMtu(iface_));
    auto src = capture::PcapSource::openLive(iface_, static_cast<int>(snaplen),
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
        // Sized from the SECOND link's own MTU: the two need not match, and a
        // shared snaplen would either cut the larger or waste slots on the smaller.
        src2 = capture::PcapSource::openLive(
            iface_secondary_,
            static_cast<int>(::tc8::net::captureSnaplenFor(iface_secondary_, 65535)),
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

    // Both sources are open and their BPF applied, so the kernel ring is
    // already receiving matching frames. The launcher is NOT signalled yet:
    // arming the ring is only half of "we can hear the DUT" on a wire that
    // prunes multicast, and the groups are named by the expectation surface
    // parsed just below. See the --ready-file write further down.

    ::tc8::TestConfig config{};
    // OEM passthrough tokens ride into the config verbatim — an out-of-tree
    // Context parses them in its own applyTestConfig overload. The strict
    // --expect loop below keeps owning the closed in-tree key set.
    config.expect_extra_tokens = expect_extra_tokens_;
    // The effective surface is the driver's identity tokens followed by this
    // case's `expect_overrides` (spec_inventory.h's fifth axis). Appending last
    // IS the mechanism: every applyExpectToken below assigns its field, so a
    // trailing token overrides the deployment default with no merge logic and
    // no precedence table. Drivers never learn the axis exists — they emit only
    // the base identity — which is what makes bash and the orchestrator unable
    // to drift on it, the same property `timing_serial` already has.
    //
    // ...and under --negative-row the case's SIXTH axis takes over instead: the
    // authored flip, then the negative run's own overrides. Same append-only
    // mechanism, and `load()` has already rejected a neg_expect_overrides that
    // would collide with — and so overwrite — the flip.
    std::vector<std::string> effective_expect = expect_tokens_;
    if (negative_row_) {
        // Fail loud rather than fall through to the positive surface: a negative
        // run that silently ran POSITIVE would report a pass and be read as "the
        // guard is not trivially-true" — the exact false reassurance this mode
        // exists to disprove.
        if (sc == nullptr || sc->neg_wrong_token.empty()) {
            std::fprintf(stderr,
                         "error: --negative-row: case %.*s has no authored negative row "
                         "(neg_wrong_token) in the inventory overrides\n",
                         static_cast<int>(entry->id.size()), entry->id.data());
            return 1;
        }
        // Out of range is refused for the same reason half a row is: a run that
        // quietly fell back to row 0 would assert the wrong verdict and report it
        // as the authored one.
        if (negative_row_index_ < 0 ||
            static_cast<std::size_t>(negative_row_index_) > sc->neg_extra_wrong_tokens.size()) {
            std::fprintf(stderr,
                         "error: --negative-row-index %d: case %.*s authors %zu row(s) "
                         "(0..%zu)\n",
                         negative_row_index_, static_cast<int>(entry->id.size()),
                         entry->id.data(), sc->neg_extra_wrong_tokens.size() + 1,
                         sc->neg_extra_wrong_tokens.size());
            return 1;
        }
        const std::string &flip =
            negative_row_index_ == 0
                ? sc->neg_wrong_token
                : sc->neg_extra_wrong_tokens[static_cast<std::size_t>(negative_row_index_) - 1];
        if (flipIsNoOp(flip, expect_tokens_)) {
            std::fprintf(stderr,
                         "error: --negative-row: the flip '%s' equals this deployment's own "
                         "--expect value for that key, so it would falsify nothing; the row's "
                         "wrong value is wrong only for the reference deployment\n",
                         flip.c_str());
            return 1;
        }
        effective_expect.push_back(flip);
        // Row 0 is the primary and the only one that carries overrides; an extra
        // row is base + its own token, which is why it needs none.
        if (negative_row_index_ == 0) {
            effective_expect.insert(effective_expect.end(), sc->neg_expect_overrides.begin(),
                                    sc->neg_expect_overrides.end());
        }
    } else if (sc != nullptr) {
        effective_expect.insert(effective_expect.end(), sc->expect_overrides.begin(),
                                sc->expect_overrides.end());
    }
    for (const auto &tok : effective_expect) {
        // Try each protocol's parser; the first that recognises the token
        // wins. ARP's parser short-circuits on the `arp.` prefix so SOME/IP
        // keys never reach it. A token unrecognised by both is a CLI error.
        if (applyExpectToken(tok, config.arp)) {
            continue;
        }
        if (applyExpectToken(tok, config.dut)) {
            continue;
        }
        if (applyExpectToken(tok, config.tester)) {
            continue;
        }
        if (applyExpectToken(tok, config.someip_dut)) {
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

    // Establish the second half of "the capture represents the wire": hold the
    // multicast groups this case must be able to hear. A passive pcap emits no
    // IGMP report, so on a snooping bridge the DUT's SD traffic is pruned before
    // it ever reaches the ring — invisible to every drop counter, and
    // indistinguishable from a silent DUT. Joining removes that cause, which is
    // what makes a later `recv == 0` a statement about the DUT.
    //
    // Held for the whole run by living in this scope, and released when it ends.
    // Joined BEFORE the launcher is told to start the DUT (below), because a
    // group joined after the first Offer has already been pruned buys nothing.
    // Derived whether or not we intend to join: declining must record what the
    // run NEEDED, not pretend it needed nothing.
    const std::vector<std::string> mcast_groups =
        ::tc8::multicastGroupsToHold(entry->bpf_group, config.someip, ::tc8::dut::kSdMcastGroup);
    auto membership = multicast_membership_
                          ? capture::MulticastMembership::join(iface_, mcast_groups)
                          : capture::MulticastMembership::declined(mcast_groups);
    // The secondary source captures the same BPF on a second broadcast domain,
    // so it needs the same groups to be able to hear the same traffic.
    auto membership2 = iface_secondary_.empty()
                           ? capture::MulticastMembership::join(iface_secondary_, {})
                       : multicast_membership_
                           ? capture::MulticastMembership::join(iface_secondary_, mcast_groups)
                           : capture::MulticastMembership::declined(mcast_groups);
    if (!mcast_groups.empty()) {
        std::string joined;
        for (const auto &g : mcast_groups) {
            joined += (joined.empty() ? "" : " ") + g;
        }
        std::printf("mcast    : %s (%s)\n", joined.c_str(),
                    membership.allHeld() ? "held" : "NOT HELD");
    }
    // NOTE — a settle interval was tried here and REMOVED as disproven.
    //
    // The hypothesis was that a snooping bridge needs time after our report
    // before it forwards, and that traffic sent meanwhile is released in a burst
    // (SOMEIPSRV_SD_BEHAVIOR_01 over an 802.11 hop reads two Offers 3-5 us apart
    // from a DUT whose repetition timer is 200 ms, and fails its gap check). It
    // is a good story and it is wrong: waiting 500 ms, 3 s and 8 s before
    // releasing the DUT each reproduced the burst exactly. What DOES fix it is a
    // membership held continuously by a separate long-lived process, which this
    // per-case join is not — cause still unidentified.
    //
    // Left absent rather than shipped at some default: a knob that plausibly
    // ought to help, measured not to, is worse than none — the next reader
    // tunes it instead of finding the real cause.
    for (const auto &f : membership.failed()) {
        std::fprintf(stderr, "warning: multicast membership on %s failed: %s\n", iface_.c_str(),
                     f.c_str());
    }
    for (const auto &f : membership2.failed()) {
        std::fprintf(stderr, "warning: multicast membership on %s failed: %s\n",
                     iface_secondary_.c_str(), f.c_str());
    }

    // NOW the launcher may start the DUT: the ring is armed AND the groups the
    // DUT will multicast to are held, so from here the harness cannot miss its
    // first frame — a guarantee a fixed startup delay could not give under CPU
    // load (SOMEIPSRV_FORMAT_02 needs the DUT's first OfferService,
    // session_id 0x0001). Signalling this after --expect parsing also means a
    // bad token fails before a launcher has spawned a DUT for nothing.
    if (!ready_file_path_.empty()) {
        if (std::FILE *rf = std::fopen(ready_file_path_.c_str(), "wb")) {
            std::fclose(rf);
        } else {
            std::fprintf(stderr, "warning: could not create --ready-file '%s'\n",
                         ready_file_path_.c_str());
        }
    }

    // ...and NOW wait for the other half. Having released the launcher to start
    // the DUT, we must not reach `kickStimulus` before it has bound the ports that
    // stimulus is aimed at. Sits here — before the runner and the DUT-control
    // backend — so the capability query below (a UT round trip) is covered too.
    // The barrier is opt-in: without `--go-file` this is a no-op and a standalone
    // harness run behaves exactly as it always did.
    if (!go_file_path_.empty()) {
        waitForDutReady(go_file_path_);
    }

    std::unique_ptr<sce::ITestRunner> runner = entry->factory(config);

    // Tier-2 DUT-control backend (--dut-control). Owned here for the run's
    // lifetime and forwarded to seam-routed stimulus; cases that drive the
    // opcode builders directly never touch it. Built once, not per-case.
    std::unique_ptr<sce::IDutControl> dut_control = sce::makeDutControl(config, iface_);

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
        // Only a DUT-DERIVED requirement is worth the OpQueryCapabilities round
        // trip. Its reply makes the DUT ARP-resolve the probe's source, and that
        // ARP lands inside the case's capture window — which an ARP-observing
        // §4.5 link-local case reads as the DUT's own Probe. Measured: declaring
        // a backend-static capability on those cases turned 11 of them from pass
        // into a false fail, with the probe's ARP as the only new frame on the
        // wire. A backend-static requirement is answerable without touching the
        // DUT, so answer it that way.
        // The topology's bits are ORed in HERE, for every backend alike, rather
        // than handed to one backend to advertise: the other one then never did,
        // and a case it ran correctly skipped as unavailable (TD-25).
        const std::uint32_t caps =
            ((entry->required_capabilities & sce::kDutDerivedCaps) != 0U
                 ? dut_control->capabilities()
                 : dut_control->staticCapabilities()) |
            sce::topologyCapabilities(config);
        if (const std::uint32_t missing = entry->required_capabilities & ~caps;
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
    // Keep the harness's own DUT-control traffic out of the verdict. The seam's
    // request/response frames ride the same wire as the protocol under test, and
    // a case that grades the first datagram in its listen window would otherwise
    // grade a control response in place of its own. The backend reports the port
    // it actually speaks on; the frames stay in the saved pcap either way,
    // because pcap_dump runs before processFrame in the loop below.
    //
    // Unless the case's verdict IS the control response — the Upper Tester
    // Confirmation family asks the DUT what it received and reads the answer off
    // the wire (`captured.has_ut_response`). For those the control channel is the
    // evidence, not noise, and withholding it would turn a measured pass into a
    // timeout. Declared per case rather than inferred: see
    // `TestCaseTraits<>::kControlPlaneRole`.
    if (entry->control_plane_role == ::tc8::sce::ControlPlaneRole::kScaffolding) {
        pipeline.setControlPlanePort(dut_control->controlPort());
    }

    // Stimulus markers (tc8/stimulus_marker.h): a case that opens its grading at
    // a step's acknowledgement gets that acknowledgement's position in the
    // stream. The acknowledgement is a control-plane frame, so the capture has to
    // see it: the control port is admitted into the filter here, once the backend
    // has said which port it speaks on, and before any stimulus runs. It stays
    // out of the verdict all the same — the pipeline withholds it and delivers
    // only the marker.
    if (runner->observesStimulusMarkers()) {
        if (entry->control_plane_role != ::tc8::sce::ControlPlaneRole::kScaffolding) {
            // An Evidence case grades control frames AS frames; the same frame
            // cannot also be a boundary marker. Refused rather than guessed.
            std::fprintf(stderr,
                         "error: case %.*s observes stimulus markers but declares "
                         "ControlPlaneRole::kEvidence; the two are exclusive\n",
                         static_cast<int>(entry->id.size()), entry->id.data());
            return 2;
        }
        pipeline.setStimulusMarkerListener(
            [&runner](const std::string &name) { runner->onStimulusApplied(name); });
        std::vector<std::uint16_t> ports(
            entry->extra_capture_udp_ports,
            entry->extra_capture_udp_ports + entry->extra_capture_udp_port_count);
        ports.push_back(dut_control->controlPort());
        const std::string marked_bpf = capture::bpf::resolveCaptureFilter(
            bpf_override, entry->bpf_expression, entry->bpf_group, ports.data(), ports.size());
        if (marked_bpf != bpf) {
            src->applyBpf(marked_bpf);
            if (src2) {
                src2->applyBpf(marked_bpf);
            }
            std::printf("bpf      : %s (DUT-control port %u admitted for stimulus markers)\n",
                        marked_bpf.c_str(), static_cast<unsigned>(dut_control->controlPort()));
        } else if (bpf_override.has_value() || !entry->bpf_expression.empty()) {
            // An explicit filter (-f/--bpf or kBpfExpression) is taken verbatim and
            // cannot be widened here; said so, because a marker that never arrives
            // leaves the case waiting on a boundary it will not see.
            std::printf("bpf      : explicit filter kept; stimulus markers need port %u in it\n",
                        static_cast<unsigned>(dut_control->controlPort()));
        }
    }

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

    // Idle-wait fd set: when a dispatch pass finds no frames the loop blocks in
    // poll() on the capture fd(s) plus every background service's fd (see
    // IPollableService::pollFd) instead of an unconditional sleep. A frame
    // arriving mid-wait wakes poll() at once, so an observed DUT frame is
    // dispatched within ~1 ms rather than after a fixed idle quantum — while the
    // 20 ms poll timeout keeps tick()'s deadline cadence exactly as before on a
    // genuinely idle wire. Built once: the source and service fds are fixed for
    // the run. A negative fd (offline handle, or a service that failed to acquire
    // one) is omitted; an empty set degrades to the original fixed sleep.
    std::vector<pollfd> idle_pfds;
    {
        auto add_pollfd = [&idle_pfds](int fd) {
            if (fd >= 0) {
                pollfd pfd{};
                pfd.fd = fd;
                pfd.events = POLLIN;
                idle_pfds.push_back(pfd);
            }
        };
        add_pollfd(src->selectableFd());
        if (src2) {
            add_pollfd(src2->selectableFd());
        }
        for (::tc8::IPollableService *svc : services) {
            add_pollfd(svc->pollFd());
        }
    }

    // Wait up to 20 ms for any capture/service fd to become readable, returning
    // the instant one does. poll() waking on POLLIN, an error, or EINTR alike
    // just re-runs the loop (which re-dispatches and re-ticks), so the return
    // value needs no inspection. An empty fd set degrades to the original sleep.
    const auto idle_wait = [&idle_pfds]() {
        if (idle_pfds.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            return;
        }
        poll(idle_pfds.data(), static_cast<nfds_t>(idle_pfds.size()), 20);
    };

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
        // immediately when no frames match — without a wait here we would burn
        // one CPU core spinning at ~10^7 ticks/sec. idle_wait() blocks up to
        // 20 ms on the capture/service fds, so the tick cadence (deadline timers
        // in seconds resolve with 1% jitter at worst) and idle-CPU cost are
        // unchanged from the prior fixed sleep, but a frame arriving mid-wait
        // wakes the loop immediately instead of after the full quantum.
        if (n == 0 && n2 == 0) {
            idle_wait();
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
                idle_wait();
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
    // Capture accounting, read once the dispatch loop is done and BEFORE any
    // trace is serialised (the evidence print and the .trace.json sidecar both
    // call dumpTraceJson below, and both must carry it). Cheap: libpcap already
    // maintains these counters, so this is a teardown read with no per-frame
    // cost. Both sources are reported — a run folding a second broadcast domain
    // into the stream loses frames just as badly if the SECOND ring overflows,
    // and only a per-source record says which one did.
    //
    // The membership state is folded in here rather than read from libpcap
    // because it is not a libpcap fact: it was established before the DUT
    // started and is the one completeness half that CANNOT be recovered after
    // the run. A group we failed to join leaves no counter behind — that is
    // precisely why it has to be carried forward as a recorded decision.
    std::vector<::tc8::CaptureStats> capture_stats;
    capture_stats.push_back(src->stats());
    capture_stats.back().multicast_groups = membership.requested();
    capture_stats.back().multicast_groups_failed = membership.failed();
    if (src2) {
        capture_stats.push_back(src2->stats());
        capture_stats.back().multicast_groups = membership2.requested();
        capture_stats.back().multicast_groups_failed = membership2.failed();
    }
    runner->setCaptureStats(capture_stats);

    ::tc8::sce::Verdict verdict = runner->verdict();
    if (!runner->isDone()) {
        verdict = SignalGuard::stopRequested()
                      ? ::tc8::sce::Verdict{::tc8::sce::VerdictClass::Error, "interrupted"}
                      : ::tc8::sce::Verdict{::tc8::sce::VerdictClass::Inconclusive,
                                            "harness_budget_exceeded"};
    }
    // A PASS decided by an ABSENCE is only as good as the capture under it.
    // Such a case concludes "the DUT did not send X within the window"; the
    // evidence for that is the window itself, so a frame the capture dropped is
    // an unobserved event and "the DUT did not send it" collapses into "we did
    // not see it" — the verdict then takes the first and silently certifies a
    // DUT that may be violating. That is the worse direction of the asymmetry:
    // a lossy capture makes a gap-MEASURING case false-FAIL (loud, someone
    // investigates), but makes an absence-ASSERTING case false-PASS (silent).
    //
    // Gated on the final transition being tick-driven, so this reaches exactly
    // the exposed population (~107 public must-not-send / ExpectNoX cases) and
    // never a pass whose own frame is the evidence — loss cannot invalidate
    // those. Downgrading to INCONCLUSIVE is the honest "not measured", not a
    // fail: the DUT was not shown to violate anything.
    //
    // The rule lives HERE, in the one place that emits the verdict, rather than
    // as a per-case `cond` — an invariant handed to 107 case authors (and every
    // future one) is an invariant that gets forgotten, and a forgotten one here
    // is a silent false pass.
    //
    // UNKNOWN counts as unproven, not as clean: `captureProvenComplete` demands
    // every source actually measured. "We could not check our own capture" is
    // not a basis for asserting an absence either.
    // "The capture represents the wire" has THREE independent halves, and an
    // absence-based pass needs all of them: nothing was DROPPED (the kernel's
    // own counters), nothing was CUT SHORT (a frame past the snaplen, which the
    // dissector refuses rather than mis-decodes — see
    // PacketPipeline::truncatedFrames), and nothing was never DELIVERED because
    // we did not hold its multicast group (tc8::CaptureStats::multicast_groups).
    // They are different holes in the same claim, so they answer the same
    // question here.
    //
    // The third is the one with no counter of its own: a pruned frame is
    // dropped by nothing and truncated by nothing, so on a snooping wire the
    // first two halves both read clean while the capture saw none of the
    // traffic. Measured — a source reporting `recv=0 drop=0 ifdrop=0` while the
    // DUT was demonstrably putting 18 frames on the wire. That is why the
    // membership is established up front and carried here as evidence rather
    // than inferred from what arrived.
    // The stimulus axis, checked FIRST because it is the more fundamental of the
    // two preconditions. The capture rule below asks whether we could have
    // OBSERVED the DUT's behaviour; this asks whether the behaviour we are
    // grading a response to was ever PROVOKED. If the stimulus never happened,
    // the case has no premise, so neither direction of verdict is about the DUT —
    // and unlike the capture rule (which only threatens an absence-based PASS)
    // this invalidates a FAIL just as much. That is the expensive direction:
    // measured, a host without iptables produced
    // `fail:event_0x8003_sent_after_tcp_connection_lost` against a DUT that was
    // behaving correctly, with a capture that appeared to corroborate it.
    //
    // Like the capture rule, it lives here rather than in each case: the scopes
    // are RAII objects built deep in case code, and an invariant that every case
    // author must remember is one that gets forgotten.
    // Applies to an already-INCONCLUSIVE verdict too, which is diagnostics rather
    // than disposition (both are non-conclusions, so no gate outcome changes).
    // Measured: with the filter uninstalled, TCP_FLAGS_INVALID_07 reported
    // `no_dut_ack_to_otw_seq_syn_in_syn_recv` — true, and a description of the
    // SYMPTOM. The DUT did not ACK because the tester's kernel was free to RST it.
    // Reporting the symptom sends an operator to look for a DUT defect; reporting
    // the unperformed stimulus sends them to their own host, which is where the
    // problem is. Naming the root cause is the whole point of the request this
    // implements: "a missing host tool did not look like a missing host tool".
    //
    // Error is deliberately left alone — a test-system fault outranks this and
    // must not be softened into a precondition note.
    if (verdict.cls != ::tc8::sce::VerdictClass::Error &&
        ::tc8::UnperformedStimulus::any()) {
        verdict = ::tc8::sce::Verdict{::tc8::sce::VerdictClass::Inconclusive,
                                      ::tc8::UnperformedStimulus::reason()};
    }
    const bool capture_whole =
        ::tc8::captureProvenComplete(capture_stats) && pipeline.truncatedFrames() == 0;
    if (verdict.cls == ::tc8::sce::VerdictClass::Pass &&
        !runner->finalTransitionWasFrameDriven() && !capture_whole) {
        const char *reason = pipeline.truncatedFrames() != 0
                                 ? "capture_truncated_frames_absence_unproven"
                             : ::tc8::anySourceLostFrames(capture_stats)
                                 ? "capture_lost_frames_absence_unproven"
                             : ::tc8::anySourceMissingMulticastMembership(capture_stats)
                                 ? "capture_multicast_group_unheld_absence_unproven"
                                 : "capture_completeness_unknown_absence_unproven";
        verdict = ::tc8::sce::Verdict{::tc8::sce::VerdictClass::Inconclusive, reason};
    }
    const std::string verdict_str = verdict.str();
    std::printf("verdict  : %s\n", verdict_str.c_str());
    // After the verdict it qualifies, before the evidence it belongs to.
    // Printed unconditionally, not only when frames were lost: a line that
    // appears solely on loss is indistinguishable from a silently broken
    // counter — the same "absence proves nothing" trap as the missing
    // measurement itself. One line per source; a clean run stays one line.
    // A truncation is loud on its own line, not folded into a per-source one:
    // it is a run-level snaplen fact, and it means frames were REFUSED — the
    // reader must not mistake a clean drop=0 for a complete capture.
    if (pipeline.truncatedFrames() != 0) {
        std::printf("capture  : %llu frame(s) exceeded the snaplen and were REFUSED — "
                    "segmentation offload is likely on; this capture does not represent "
                    "the wire\n",
                    static_cast<unsigned long long>(pipeline.truncatedFrames()));
    }
    // Informational, and deliberately NOT a verdict qualifier: these frames were
    // captured and saved, they were simply not offered to the state machine. It
    // is printed because "which frames reached the verdict" was the question that
    // cost the most to answer when a control response was being graded in place
    // of a case's own datagram — a line here answers it without a pcap.
    if (pipeline.controlPlaneFrames() != 0) {
        std::printf("capture  : %llu frame(s) on the DUT-control port withheld from grading "
                    "(still in the saved pcap)\n",
                    static_cast<unsigned long long>(pipeline.controlPlaneFrames()));
    }
    for (const auto &cs : capture_stats) {
        if (!cs.available) {
            std::printf("capture  : %s stats unavailable\n", cs.iface.c_str());
            continue;
        }
        std::printf("capture  : %s recv=%u drop=%u ifdrop=%u%s\n", cs.iface.c_str(),
                    cs.frames_received, cs.frames_dropped_ring, cs.frames_dropped_iface,
                    cs.lostFrames() ? "  WARNING: frames lost — a gap-derived verdict on this "
                                      "run may be measured from a late anchor"
                                    : "");
    }
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
    // pcap so `tc8-harness decode-pcap` can merge it (verbatim, under
    // ``captured_trace``) into the per-case JSON it produces for the site. The
    // sidecar path is the pcap path with ``.pcap`` replaced by ``.trace.json``
    // (or ``<pcap>.trace.json`` when there's no .pcap suffix). Skipped silently
    // when --pcap-dump wasn't requested — a run without a retained pcap has no
    // frame-idx correlation anchor, so the site walker has no use for the
    // trace. This trace is the single source of truth for the site's timeline
    // labels (generate_messages.py::_label_via_trace); the site does NOT
    // re-decode the wire. See docs/tech-debt.md TD-05.
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
