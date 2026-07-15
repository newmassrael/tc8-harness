#include "cli/testability_send_command.h"

#include <cctype>
#include <cstdio>
#include <string>
#include <vector>

#include <arpa/inet.h>

#include "tc8/testability_client.h"
#include "tc8/testability_protocol.h"

namespace tc8::cli {

namespace {

namespace tp = tc8::testability;

// PRS_TPSP §6.8 Result IDs, named. A bare "rid=0xFF" makes the reader open the
// spec; "E_NTF (service primitive not found)" is the same byte with the meaning
// attached. Unknown values print as the raw byte rather than being forced into a
// name — a DUT built against a newer revision may answer one this build predates.
const char *ridName(std::uint8_t rid) {
    switch (rid) {
        case tp::kRidEOk:  return "E_OK (performed successfully)";
        case tp::kRidENok: return "E_NOK (general error)";
        case tp::kRidENtf: return "E_NTF (service primitive not found)";
        case tp::kRidEPen: return "E_PEN (Upper Tester / SP pending)";
        case tp::kRidEIsb: return "E_ISB (insufficient buffer size)";
        case tp::kRidEInv: return "E_INV (invalid input or parameter)";
        case tp::kRidEIsd: return "E_ISD (invalid socket ID)";
        case tp::kRidEUcs: return "E_UCS (unable to create / no free socket)";
        case tp::kRidEUbs: return "E_UBS (unable to bind, port taken)";
        case tp::kRidEIif: return "E_IIF (invalid network / virtual interface)";
        default:           return nullptr;
    }
}

// Parse a hex DAT. Accepts the shapes a human actually types when copying bytes
// out of a spec table or a capture: "A1B2C3", "a1 b2 c3", "A1:B2:C3", "a1-b2-c3".
// Separators are dropped, not interpreted, so a stray one cannot silently shift
// the byte boundaries — an odd digit count is an error, never a zero-padded guess.
bool parseHexDat(const std::string &in, std::vector<std::uint8_t> &out,
                 std::string &err) {
    std::string digits;
    digits.reserve(in.size());
    for (const char c : in) {
        if (c == ' ' || c == ':' || c == '-' || c == '_') {
            continue;
        }
        if (std::isxdigit(static_cast<unsigned char>(c)) == 0) {
            err = std::string("not a hex digit: '") + c + "'";
            return false;
        }
        digits.push_back(c);
    }
    if (digits.size() % 2 != 0) {
        err = "odd number of hex digits (" + std::to_string(digits.size()) +
              ") — each byte needs two";
        return false;
    }
    out.clear();
    out.reserve(digits.size() / 2);
    for (std::size_t i = 0; i < digits.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(
            std::stoul(digits.substr(i, 2), nullptr, 16)));
    }
    return true;
}

void printHex(const std::vector<std::uint8_t> &bytes) {
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        std::printf("%s%02X", (i != 0 && i % 16 == 0) ? "\n                " : (i != 0 ? " " : ""),
                    static_cast<unsigned>(bytes[i]));
    }
}

}  // namespace

TestabilitySendCommand::TestabilitySendCommand(CLI::App &app) {
    sub_ = app.add_subcommand(
        "testability-send",
        "Send one AUTOSAR Testability service primitive (--gid/--pid/--dat) "
        "and print the decoded Response. The addressable counterpart to "
        "testability-probe's fixed sweep — reaches any group, including a "
        "non-standard OEM one");
    sub_->add_option("--dut-ip", dut_ip_, "DUT IPv4 address")->required();
    sub_->add_option("--gid", gid_,
                     "Service group ID, 0x00-0x7F (PRS_TPSP §6.9; standard "
                     "groups from 0x00, non-standard down from 0x7F)")
        ->required();
    sub_->add_option("--pid", pid_,
                     "Service primitive ID within the group, 0x00-0xFF")
        ->required();
    sub_->add_option("--dat", dat_hex_,
                     "Request parameters as hex bytes (e.g. A1B2C3, "
                     "'a1 b2 c3', A1:B2:C3). Omit for a primitive that takes "
                     "none");
    sub_->add_option("--port", port_,
                     "Testability UDP/TCP port (default: protocol constant 30700)");
    sub_->add_option("--service-id", service_id_,
                     "Testability Service ID (default: 0x0105)");
    sub_->add_option("-t,--timeout", timeout_ms_, "Reply timeout in milliseconds")
        ->capture_default_str();
    sub_->add_flag("--tcp", use_tcp_, "Carry SOME/IP over TCP instead of UDP");
    sub_->add_option("--source-ip", source_ip_,
                     "Bind the request's source to this local IPv4 address "
                     "(default: kernel-chosen)");
}

int TestabilitySendCommand::run() {
    in_addr addr{};
    if (::inet_pton(AF_INET, dut_ip_.c_str(), &addr) != 1) {
        std::fprintf(stderr, "testability-send: invalid DUT IPv4 address '%s'\n",
                     dut_ip_.c_str());
        return 1;
    }
    in_addr src_addr{};
    if (!source_ip_.empty() &&
        ::inet_pton(AF_INET, source_ip_.c_str(), &src_addr) != 1) {
        std::fprintf(stderr, "testability-send: invalid source IPv4 address '%s'\n",
                     source_ip_.c_str());
        return 1;
    }
    // GID is a 7-bit field: methodId() masks it to 0x7F, so a larger value would
    // be silently truncated and address a different group than the one asked for.
    // Reject instead — a typo must not quietly probe the wrong group.
    if (gid_ < 0 || gid_ > 0x7F) {
        std::fprintf(stderr,
                     "testability-send: --gid %d is out of range (0x00-0x7F; it "
                     "is a 7-bit field)\n",
                     gid_);
        return 1;
    }
    if (pid_ < 0 || pid_ > 0xFF) {
        std::fprintf(stderr, "testability-send: --pid %d is out of range (0x00-0xFF)\n",
                     pid_);
        return 1;
    }
    std::vector<std::uint8_t> dat;
    std::string err;
    if (!dat_hex_.empty() && !parseHexDat(dat_hex_, dat, err)) {
        std::fprintf(stderr, "testability-send: --dat: %s\n", err.c_str());
        return 1;
    }

    stimulus::TestabilityConfig cfg;
    cfg.dut_ip_be = addr.s_addr;
    cfg.dut_port = port_ > 0 ? static_cast<std::uint16_t>(port_) : tp::kDefaultPort;
    cfg.service_id = service_id_ > 0 ? static_cast<std::uint16_t>(service_id_)
                                     : tp::kDefaultServiceId;
    cfg.use_tcp = use_tcp_;

    const auto resp = stimulus::testabilityCall(
        cfg, static_cast<std::uint8_t>(gid_), static_cast<std::uint8_t>(pid_), dat,
        timeout_ms_, src_addr.s_addr);

    if (!resp.ok) {
        std::fprintf(stderr,
                     "testability-send: no well-formed Response from %s:%u "
                     "within %d ms over %s (DUT down, testability not "
                     "implemented, or port/service-id mismatch)\n",
                     dut_ip_.c_str(), cfg.dut_port, timeout_ms_,
                     use_tcp_ ? "TCP" : "UDP");
        return 1;
    }

    const char *name = ridName(resp.rid);
    std::printf("testability-send: %s:%u GID 0x%02X PID 0x%02X -> rid=0x%02X %s\n",
                dut_ip_.c_str(), cfg.dut_port, static_cast<unsigned>(gid_),
                static_cast<unsigned>(pid_), static_cast<unsigned>(resp.rid),
                name != nullptr ? name : "(unknown Result ID)");
    if (!resp.dat.empty()) {
        std::printf("  response dat (%zu B): ", resp.dat.size());
        printHex(resp.dat);
        std::printf("\n");
    }
    // A non-E_OK RID is a real answer from a live DUT, printed above; the exit
    // code reports whether the primitive SUCCEEDED, which is what a script tests.
    return resp.rid == tp::kRidEOk ? 0 : 1;
}

}  // namespace tc8::cli
