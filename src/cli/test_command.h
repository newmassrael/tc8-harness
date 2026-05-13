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
    // gap report against doc/spec/case_inventory.json.
    bool vs_spec_ = false;
    bool vs_spec_strict_ = false;
    // `--list-cases --exclude-deferred` strips harness-registered cases
    // whose canonical ID is marked `expected:false` in
    // doc/spec/inventory_overrides.json — single source of truth for
    // CI/smoke skip lists. Without this flag, the dump shows every
    // registered case regardless of override status.
    bool exclude_deferred_ = false;
    // `--list-cases --exclude-linux-known-fail` strips cases marked
    // `linux_known_fail:true` in doc/spec/inventory_overrides.json —
    // platform-specific failures on a Linux DUT (kernel/userland
    // deviations from RFC MUST/SHOULD) that pass on a strict-RFC DUT.
    // Independent from `--exclude-deferred`; both can be combined.
    // Spec coverage (`--vs-spec`) ignores this axis so reports stay
    // honest about what the harness covers.
    bool exclude_linux_known_fail_ = false;
    std::string inventory_path_;
    std::string overrides_path_;
    // Raw `KEY=VALUE` tokens collected from `--expect`. Parsed and pushed
    // into ITestRunner::seedExpectations() inside runCase().
    std::vector<std::string> expect_tokens_;

    // Stimulus timing knobs — optional so unset values inherit
    // `SdBootTiming{}` defaults inside TestConfig. Used by §5.1 cases with
    // tester-initiated packet emits (FORMAT_12/13); real DUTs with slower
    // SD init override `--stimulus-wait` to widen the initial pause.
    std::optional<int> stimulus_wait_ms_;
    std::optional<int> stimulus_retry_ms_;
    std::optional<int> stimulus_emits_;

    // Optional pcap-file dump of every captured frame for post-mortem
    // debugging of flaky cases. Empty = off. Must be a writable path.
    std::string pcap_dump_path_;
};

}  // namespace tc8::cli
