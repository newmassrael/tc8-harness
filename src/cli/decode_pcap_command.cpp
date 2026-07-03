#include "cli/decode_pcap_command.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <pcap/pcap.h>

#include "tc8/captured_event.h"

#include "capture/pcap_source.h"
#include "cli/packet_summary.h"                // Candidate + makeCandidate (presentation layer, TD-08)
#include "dissect/packet_pipeline.h"
#include "sce_integration/captured_trace.h"    // tc8::sce::appendJsonEscaped (JSON escaping)
#include "wire/wire_format.h"                   // tc8::wire::ipv4ToDotted / macToHex (neutral leaf, TD-10)

namespace tc8::cli {

namespace {

// MAC and captured-uint32 (octet 0 in the low byte) dotted-quad formatting
// reuse the harness SSOT cores tc8::wire::macToHex / tc8::wire::ipv4ToDotted, so
// this command holds no second copy of that byte ordering. The per-protocol
// summary builders and candidate selection live in cli/packet_summary.* (TD-08);
// this TU keeps only JSON assembly, endpoint auto-detection, and the drive loop.
using ::tc8::wire::ipv4ToDotted;
using ::tc8::wire::macToHex;

void appendJsonString(std::string &out, std::string_view s) {
    out.push_back('"');
    ::tc8::sce::appendJsonEscaped(out, s);
    out.push_back('"');
}

// Minimal structural well-formedness check for the harness trace sidecar (the
// harness avoids a JSON library, so this is not a full RFC 8259 parser). It
// confirms `s` is a single brace-balanced JSON object with well-formed string
// literals — enough to guarantee that splicing it in as a value keeps the
// surrounding PacketCapture document parseable. Its job is to catch the
// realistic corruption (a truncated or non-JSON sidecar from an interrupted
// write), so a malformed trace is dropped with a warning rather than silently
// emitting an invalid artifact (the retired decode_pcap.py validated via
// json.loads for the same reason).
bool isWellFormedJsonObject(std::string_view s) {
    auto isws = [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; };
    std::size_t i = 0;
    const std::size_t n = s.size();
    while (i < n && isws(s[i])) ++i;
    if (i >= n || s[i] != '{') return false;
    int depth = 0;
    bool in_str = false;
    bool escaped = false;
    bool closed = false;
    for (; i < n; ++i) {
        const char c = s[i];
        if (closed) {
            if (!isws(c)) return false;  // trailing content after the top-level object
            continue;
        }
        if (in_str) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') {
            in_str = true;
        } else if (c == '{' || c == '[') {
            ++depth;
        } else if (c == '}' || c == ']') {
            if (--depth < 0) return false;
            if (depth == 0) closed = true;
        }
    }
    return closed && !in_str && depth == 0;
}

// ---------------------------------------------------------------------------
// Per-frame record assembled from the pipeline's variant events for one frame.
// ---------------------------------------------------------------------------

struct PacketRec {
    int idx = 0;
    long long ts_us = 0;
    long long ts_delta_us = 0;
    std::string src_mac;  // empty => emitted as null
    std::string dst_mac;
    std::optional<std::uint32_t> src_ip;  // captured-uint32 (octet0 in low byte)
    std::optional<std::uint32_t> dst_ip;
    std::string protocol = "UNKNOWN";
    std::string summary;
    std::string direction = "other";
};

// Per-frame protocol/summary/endpoint selection (the deepest candidate + the
// raw-Ethernet fallback) lives in packet_summary.cpp::chooseFrameView; this
// command just copies the FrameView into its PacketRec.

// ---------------------------------------------------------------------------
// Direction + endpoint auto-detection (mirror decode_pcap.py).
// ---------------------------------------------------------------------------

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string directionOf(const std::string &src_mac, const std::string &dst_mac,
                        const std::string &tester_mac, const std::string &dut_mac) {
    const std::string s = toLower(src_mac);
    const std::string d = toLower(dst_mac);
    const std::string t = toLower(tester_mac);
    const std::string dm = toLower(dut_mac);
    if (!t.empty() && s == t) return "tester_to_dut";
    if (!dm.empty() && s == dm) return "dut_to_tester";
    if (!t.empty() && d == t) return "dut_to_tester";
    if (!dm.empty() && d == dm) return "tester_to_dut";
    return "other";
}

struct Endpoints {
    std::string tester_mac, dut_mac, tester_ip, dut_ip;
};

// Infer (tester, dut) from the capture: the two most frequent unicast src MACs
// are the endpoints; the one that emits first is the tester. IPs are the first
// src_ip seen sourced from each detected MAC.
Endpoints autodetect(const std::vector<PacketRec> &recs) {
    struct Acc {
        int count = 0;
        int first_seen = 0;
        int insert_order = 0;
        std::string ip;
    };
    std::unordered_map<std::string, Acc> by_mac;
    int order = 0;
    for (const auto &r : recs) {
        const std::string mac = toLower(r.src_mac);
        if (mac.empty() || mac == "00:00:00:00:00:00") continue;
        unsigned first_byte = 0;
        if (std::sscanf(mac.c_str(), "%2x", &first_byte) != 1) continue;
        if ((first_byte & 0x01u) != 0) continue;  // multicast / broadcast bit
        auto it = by_mac.find(mac);
        if (it == by_mac.end()) {
            Acc a;
            a.first_seen = r.idx;
            a.insert_order = order++;
            if (r.src_ip.has_value()) a.ip = ipv4ToDotted(*r.src_ip);
            by_mac.emplace(mac, a);
            it = by_mac.find(mac);
        } else if (it->second.ip.empty() && r.src_ip.has_value()) {
            it->second.ip = ipv4ToDotted(*r.src_ip);
        }
        it->second.count++;
    }
    if (by_mac.empty()) return {};

    std::vector<std::pair<std::string, Acc>> ranked(by_mac.begin(), by_mac.end());
    std::sort(ranked.begin(), ranked.end(), [](const auto &a, const auto &b) {
        if (a.second.count != b.second.count) return a.second.count > b.second.count;
        return a.second.insert_order < b.second.insert_order;
    });

    Endpoints ep;
    if (ranked.size() == 1) {
        ep.tester_mac = ranked[0].first;
        ep.tester_ip = ranked[0].second.ip;
        return ep;
    }
    const auto &a = ranked[0];
    const auto &b = ranked[1];
    const bool a_first = a.second.first_seen <= b.second.first_seen;
    const auto &tester = a_first ? a : b;
    const auto &dut = a_first ? b : a;
    ep.tester_mac = tester.first;
    ep.tester_ip = tester.second.ip;
    ep.dut_mac = dut.first;
    ep.dut_ip = dut.second.ip;
    return ep;
}

long long absTsUs(const pcap_pkthdr &hdr, int precision) {
    const long long subsec = precision == PCAP_TSTAMP_PRECISION_NANO
                                 ? static_cast<long long>(hdr.ts.tv_usec) / 1000LL
                                 : static_cast<long long>(hdr.ts.tv_usec);
    return static_cast<long long>(hdr.ts.tv_sec) * 1'000'000LL + subsec;
}

}  // namespace

DecodePcapCommand::DecodePcapCommand(CLI::App &app) {
    sub_ = app.add_subcommand(
        "decode-pcap",
        "Decode a saved pcap into the documentation site's PacketCapture JSON "
        "(replaces site/scripts/decode_pcap.py; see docs/tech-debt.md TD-05)");
    sub_->add_option("case_id", case_id_, "Case ID (uppercased into the output)")->required();
    sub_->add_option("outcome", outcome_, "Run outcome")
        ->required()
        ->check(CLI::IsMember({"pass", "fail"}));
    sub_->add_option("pcap_file", pcap_file_, "Path to the saved .pcap")
        ->required()
        ->check(CLI::ExistingFile);
    sub_->add_option("--out", out_path_, "Output JSON path")->required();
    sub_->add_option("--captured-at", captured_at_, "ISO-8601 capture timestamp (display only)");
    sub_->add_option("--trace-json", trace_json_path_,
                     "Harness transition-trace sidecar (<pcap>.trace.json). Merged "
                     "verbatim under \"captured_trace\"; absent path is ignored.");
    sub_->add_option("--tester-mac", tester_mac_, "Tester MAC (default: auto-detect)");
    sub_->add_option("--tester-ip", tester_ip_, "Tester IPv4 (default: auto-detect)");
    sub_->add_option("--dut-mac", dut_mac_, "DUT MAC (default: auto-detect)");
    sub_->add_option("--dut-ip", dut_ip_, "DUT IPv4 (default: auto-detect)");
}

int DecodePcapCommand::run() {
    auto src = capture::PcapSource::openOffline(pcap_file_);
    const int dlt = src->datalink();
    const int precision = src->tstampPrecision();

    // The listener builds each event's presentation candidate eagerly, while
    // the event's non-owning payload pointer is still valid (it dangles once
    // processFrame returns). chooseCandidate then picks the deepest per frame.
    std::vector<Candidate> frame_cands;
    dissect::PacketPipeline pipeline(
        [&frame_cands](const ::tc8::CapturedEvent &ev) { frame_cands.push_back(makeCandidate(ev)); });
    pipeline.setTstampPrecision(precision);

    std::vector<PacketRec> recs;
    long long first_ts = -1;
    long long prev_ts = -1;
    int idx = 0;

    while (true) {
        const int n = src->dispatch(
            /*max_frames=*/-1, [&](const pcap_pkthdr &hdr, const u_char *data) {
                const long long ts = absTsUs(hdr, precision);
                if (first_ts < 0) {
                    first_ts = ts;
                    prev_ts = ts;
                }
                PacketRec r;
                r.idx = idx;
                r.ts_us = ts - first_ts;
                r.ts_delta_us = idx > 0 ? (ts - prev_ts) : 0;

                std::uint16_t ethertype = 0;
                if (hdr.caplen >= 14u) {
                    r.dst_mac = macToHex(data);
                    r.src_mac = macToHex(data + 6);
                    ethertype = static_cast<std::uint16_t>(
                        (static_cast<unsigned>(data[12]) << 8) | data[13]);
                }

                frame_cands.clear();
                pipeline.processFrame(hdr, data, dlt);
                const FrameView view = chooseFrameView(frame_cands, ethertype, hdr.caplen);
                r.protocol = view.protocol;
                r.summary = view.summary;
                r.src_ip = view.src_ip;
                r.dst_ip = view.dst_ip;

                recs.push_back(std::move(r));
                prev_ts = ts;
                ++idx;
            });
        if (n < 0) {
            if (n == -2) break;  // pcap_breakloop
            std::fprintf(stderr, "dispatch error: %s\n", src->lastError());
            return 1;
        }
        if (n == 0 && src->isOffline()) break;  // end of pcap
    }

    // Endpoint identities: CLI override else auto-detect from the capture.
    const Endpoints det = autodetect(recs);
    const std::string tester_mac = tester_mac_.empty() ? det.tester_mac : tester_mac_;
    const std::string dut_mac    = dut_mac_.empty()    ? det.dut_mac    : dut_mac_;
    const std::string tester_ip  = tester_ip_.empty()  ? det.tester_ip  : tester_ip_;
    const std::string dut_ip     = dut_ip_.empty()     ? det.dut_ip     : dut_ip_;

    for (auto &r : recs) {
        r.direction = directionOf(r.src_mac, r.dst_mac, tester_mac, dut_mac);
    }

    std::string case_id_upper = case_id_;
    std::transform(case_id_upper.begin(), case_id_upper.end(), case_id_upper.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    // Build the PacketCapture JSON (one packet object per line for readable
    // git diffs on the committed pcap-data branch).
    std::string out;
    out.reserve(recs.size() * 160 + 512);
    out.append("{\n");
    out.append("  \"case_id\": ");      appendJsonString(out, case_id_upper);   out.append(",\n");
    out.append("  \"outcome\": ");      appendJsonString(out, outcome_);        out.append(",\n");
    out.append("  \"captured_at\": ");  appendJsonString(out, captured_at_);    out.append(",\n");
    auto emitTop = [&](const char *key, const std::string &v) {
        out.append("  \"");
        out.append(key);
        out.append("\": ");
        if (v.empty()) {
            out.append("null");
        } else {
            appendJsonString(out, v);
        }
        out.append(",\n");
    };
    emitTop("tester_mac", tester_mac);
    emitTop("tester_ip", tester_ip);
    emitTop("dut_mac", dut_mac);
    emitTop("dut_ip", dut_ip);

    out.append("  \"packets\": [");
    for (std::size_t i = 0; i < recs.size(); ++i) {
        const auto &r = recs[i];
        out.append(i == 0 ? "\n    {" : ",\n    {");
        out.append("\"idx\": ");           out.append(std::to_string(r.idx));
        out.append(", \"ts_us\": ");       out.append(std::to_string(r.ts_us));
        out.append(", \"ts_delta_us\": "); out.append(std::to_string(r.ts_delta_us));
        out.append(", \"direction\": ");   appendJsonString(out, r.direction);
        out.append(", \"src_mac\": ");
        if (r.src_mac.empty()) out.append("null"); else appendJsonString(out, r.src_mac);
        out.append(", \"dst_mac\": ");
        if (r.dst_mac.empty()) out.append("null"); else appendJsonString(out, r.dst_mac);
        out.append(", \"src_ip\": ");
        if (r.src_ip.has_value()) appendJsonString(out, ipv4ToDotted(*r.src_ip)); else out.append("null");
        out.append(", \"dst_ip\": ");
        if (r.dst_ip.has_value()) appendJsonString(out, ipv4ToDotted(*r.dst_ip)); else out.append("null");
        out.append(", \"protocol\": ");    appendJsonString(out, r.protocol);
        out.append(", \"summary\": ");     appendJsonString(out, r.summary);
        out.append("}");
    }
    out.append(recs.empty() ? "]" : "\n  ]");

    // Evidence Export: merge the harness transition trace verbatim. The harness
    // writes well-formed JSON (test_runner.h::dumpTraceJson); a missing/empty
    // sidecar is silently skipped (the site walker then has no trace block).
    if (!trace_json_path_.empty()) {
        std::error_code ec;
        if (std::filesystem::exists(trace_json_path_, ec)) {
            if (FILE *fp = std::fopen(trace_json_path_.c_str(), "rb")) {
                std::string trace;
                char chunk[4096];
                std::size_t got = 0;
                while ((got = std::fread(chunk, 1, sizeof(chunk), fp)) > 0) {
                    trace.append(chunk, got);
                }
                std::fclose(fp);
                // Trim trailing whitespace/newline so the embedded value is tidy.
                while (!trace.empty() && (trace.back() == '\n' || trace.back() == '\r' ||
                                          trace.back() == ' ' || trace.back() == '\t')) {
                    trace.pop_back();
                }
                if (isWellFormedJsonObject(trace)) {
                    out.append(",\n  \"captured_trace\": ");
                    out.append(trace);
                } else if (!trace.empty()) {
                    std::fprintf(stderr,
                                 "warning: trace sidecar '%s' is not well-formed "
                                 "JSON; omitting captured_trace\n",
                                 trace_json_path_.c_str());
                }
            }
        }
    }

    out.append("\n}\n");

    const std::filesystem::path out_path(out_path_);
    if (out_path.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(out_path.parent_path(), ec);
    }
    FILE *fp = std::fopen(out_path_.c_str(), "wb");
    if (fp == nullptr) {
        std::fprintf(stderr, "error: cannot open output '%s'\n", out_path_.c_str());
        return 1;
    }
    std::fwrite(out.data(), 1, out.size(), fp);
    std::fclose(fp);
    std::printf("wrote %zu packet(s) to %s\n", recs.size(), out_path_.c_str());
    return 0;
}

}  // namespace tc8::cli
