#pragma once

#include <optional>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>

namespace tc8::cli {

class TestCommand {
public:
    explicit TestCommand(CLI::App &app);

    bool parsed() const {
        return sub_->parsed();
    }

    // `bpf_override` lets the user pin a filter via top-level `-f`; when
    // empty, the filter is derived from the selected case's BpfGroup.
    int run(std::optional<std::string> bpf_override);

private:
    int runListCases() const;
    int runVsSpecReport() const;
    int runCase(std::optional<std::string> bpf_override);

    CLI::App *sub_ = nullptr;
    std::string case_id_;
    std::string iface_;
    // §4.7.6.5 USAGE_01 / RFC 2131 §3.6: optional second NIC for the
    // multi-interface DHCP procedure. Empty = single-iface case
    // (today's path, every other RFC 2131 §4.x case). When set, the harness
    // opens a second `PcapSource` and dispatches it round-robin with
    // the primary iface — both feed the same pipeline so SCXML guards
    // see a unified time-ordered event stream. Stimulus injection uses
    // the primary iface only (the tc8-dut UT server binds INADDR_ANY,
    // dispatch by `iface_index` UT byte).
    std::string iface_secondary_;
    int timeout_s_ = 10;
    bool list_cases_ = false;
    bool list_all_ = false;
    // `--list-cases --vs-spec` swaps the per-case dump for a coverage
    // gap report against docs/spec/case_inventory.json.
    bool vs_spec_ = false;
    bool vs_spec_strict_ = false;
    // `--list-cases --exclude-deferred` strips harness-registered cases
    // whose canonical ID is marked `expected:false` in
    // docs/spec/inventory_overrides.json — single source of truth for
    // CI/smoke skip lists. Without this flag, the dump shows every
    // registered case regardless of override status.
    bool exclude_deferred_ = false;
    // `--list-cases --exclude-platform-known-fail` strips cases marked
    // `platform_known_fail:true` in the active inventory overrides JSON
    // (default file describes the Linux reference DUT; per-DUT files
    // selected via --inventory-overrides own their platform's entries)
    // — platform-specific DUT-stack deviations from RFC MUST/SHOULD
    // that pass on a strict-RFC DUT. Independent from
    // `--exclude-deferred`; both can be combined. Spec coverage
    // (`--vs-spec`) ignores this axis so reports stay honest about
    // what the harness covers.
    bool exclude_platform_known_fail_ = false;
    // `--list-cases --exclude-serial` strips cases marked `timing_serial:true`
    // (sub-second cadence measurements) from the parallel lane;
    // `--list-cases --only-serial` keeps ONLY those — CI runs them at
    // `--workers 1` so the reference DUT is not CPU-starved. Mutually
    // exclusive in use; combinable with the other axes' filters.
    bool exclude_serial_ = false;
    bool only_serial_ = false;
    // `--only-secondary-iface`: keep only cases marked requires_secondary_iface
    // (TC8 Topology 2 dual-iface). The smoke harness lists these to decide which
    // need a second tester veth + `--interface-secondary` — data-driven, not by
    // hardcoded case-ID.
    bool only_secondary_iface_ = false;
    // `--negative-row`: this invocation is the case's negative row — the driver
    // has flipped one --expect value to a deliberately wrong one to prove the
    // guard is not trivially-true (smoke-test.sh `run_negative_case`). It
    // suppresses the case's `expect_overrides`, which describe the POSITIVE run
    // and would otherwise be appended after the flip and overwrite it. NOT
    // related to a `_NEG`-suffixed case, which is a separately registered
    // firmware-fault-injection mutant.
    bool negative_row_ = false;
    std::string inventory_path_;
    std::string overrides_path_;
    // `--inventory-extra` (repeatable) — D5 out-of-tree injection hook.
    // Additional inventory JSONs whose cases merge into the `--vs-spec`
    // gap report alongside the primary TC8 inventory. Mirrors the
    // CMake `TC8_EXTRA_CASE_DIRS` consumer idiom: an OEM that injects
    // cases out-of-tree ships a matching inventory here so its cases
    // cross-check as in-spec instead of polluting the
    // `registered-but-not-in-spec` list. Empty = primary inventory only.
    std::vector<std::string> inventory_extra_paths_;
    // Raw `KEY=VALUE` tokens collected from `--expect`. Parsed and pushed
    // into ITestRunner::seedExpectations() inside runCase().
    std::vector<std::string> expect_tokens_;
    // Raw `KEY=VALUE` tokens from `--expect-extra` — out-of-tree OEM
    // passthrough. Not validated against the in-tree key set; carried into
    // `TestConfig::expect_extra_tokens` for an OEM Context's own
    // `applyTestConfig` overload to parse. See expect_parser.h
    // `applyExpectTokens`.
    std::vector<std::string> expect_extra_tokens_;

    // Stimulus timing knobs — optional so unset values inherit
    // `BootTiming{}` defaults inside TestConfig. Used by §5.1 cases with
    // tester-initiated packet emits (FORMAT_12/13); real DUTs with slower
    // SD init override `--stimulus-wait` to widen the initial pause.
    std::optional<int> stimulus_wait_ms_;
    std::optional<int> stimulus_retry_ms_;
    std::optional<int> stimulus_emits_;

    // Optional pcap-file dump of every captured frame for post-mortem
    // debugging of flaky cases. Empty = off. Must be a writable path.
    std::string pcap_dump_path_;

    // `--dut-control` backend selector for the Tier-2 seam: "opcode"
    // (default, in-house Upper Tester) or "testability" (AUTOSAR
    // Testability Protocol). Mapped to TestConfig::dut_control_backend in
    // runCase(); CLI11 IsMember-validated so a typo errors at parse time.
    std::string dut_control_ = "opcode";
};

}  // namespace tc8::cli
