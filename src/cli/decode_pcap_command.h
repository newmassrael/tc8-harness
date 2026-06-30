#pragma once

#include <string>

#include <CLI/CLI.hpp>

namespace tc8::cli {

// `tc8-harness decode-pcap` — offline pcap → site PacketCapture JSON exporter.
//
// Replaces the documentation site's second Python wire decoder
// (site/scripts/decode_pcap.py): the conformance harness owns the single
// authoritative wire decoder (src/dissect + *_captured.h), so the site's
// per-case capture view is produced by replaying the saved pcap through that
// same `dissect::PacketPipeline` rather than re-decoding the frames in Python.
// See docs/tech-debt.md TD-05 (and the TD-01/02/04 mirrors it collapses).
//
// The emitted JSON matches `site/src/lib/types.ts` PacketCapture: per-frame
// idx / timestamps / direction / endpoints / protocol / summary. The site's
// auto-label walker (generate_messages.py::_label_via_trace) renders timeline
// labels from the harness transition trace (the `captured_trace` block, merged
// verbatim from the `<pcap>.trace.json` sidecar), not from per-frame field
// re-evaluation, so the exporter emits no `fields` dict.
//
// CLI shape mirrors the retired decode_pcap.py so the CI invocation is a
// straight command substitution:
//   tc8-harness decode-pcap <CASE_ID> <pass|fail> <pcap_file> --out <json>
//       [--captured-at <iso8601>] [--trace-json <sidecar>]
//       [--tester-mac M --tester-ip A --dut-mac M --dut-ip A]
// Endpoint identities are auto-detected from the capture when not given
// (the harness assigns random locally-administered veth MACs per run).
class DecodePcapCommand {
public:
    explicit DecodePcapCommand(CLI::App &app);

    bool parsed() const { return sub_->parsed(); }
    int run();

private:
    CLI::App *sub_ = nullptr;

    std::string case_id_;
    std::string outcome_;
    std::string pcap_file_;
    std::string out_path_;
    std::string captured_at_;
    std::string trace_json_path_;
    std::string tester_mac_;
    std::string tester_ip_;
    std::string dut_mac_;
    std::string dut_ip_;
};

}  // namespace tc8::cli
