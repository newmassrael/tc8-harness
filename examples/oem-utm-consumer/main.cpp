// Out-of-tree consumer of the tc8-utm SDK — the shape a separate, private OEM
// repository takes: include the installed public headers, host a ProtocolServer
// on the POSIX backend, attach an OEM service-group MiddlewareModule, compose the
// exported AUTOSAR engines, and drive the whole thing over the wire through the
// exported tester-side client.
//
// What the wire round trip adds over a build-only check, stated exactly: linking
// tc8::tc8_testability_client already proves the client archive ships, and
// compiling against middleware.h already proves the codec header ships (it
// includes it) — the link and the compile catch those. What neither can reach is
// whether the endpoint BINDS, dispatches a real datagram to the registered
// module, and returns that module's own answer. That is the property an OEM
// deployment actually depends on, and only a request/response demonstrates it.
//
// So this binary gates both halves of the SDK — endpoint and client — by driving
// them: a failed round trip returns non-zero and utm_export_smoke fails. The
// AUTOSAR engines below remain link-only coverage; asserting their values is the
// unit tests' job (see the sink at the end of main).

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "tc8/posix_socket_backend.h"
#include "tc8/testability_client.h"
#include "tc8/testability/middleware.h"
#include "tc8/testability/protocol_server.h"
#include "tc8/autosar/aes_cmac.h"
#include "tc8/autosar/pn_filter.h"
#include "tc8/autosar/crc.h"
#include "tc8/autosar/e2e.h"
#include "tc8/autosar/com.h"
#include "tc8/autosar/nm.h"
#include "tc8/autosar/someiptp.h"

namespace {

// A minimal OEM group (PRS_TPSP §6.6: non-standard groups count down from 0x7F).
// A real OEM module would compose the AUTOSAR engines + its proprietary config;
// here it answers one primitive with a pure transform, so the example needs no
// OEM content while still proving the module's own handler ran.
constexpr std::uint8_t kOemGroupHigh = 0x7F;

// The module's one primitive: respond with the request DAT reversed. A transform
// rather than an echo so the assertion cannot be satisfied by request bytes
// arriving back some other way — only this handler produces this answer.
constexpr std::uint8_t kOemPidReverse = 0x01;

// Deliberately BELOW the Linux ephemeral range (net.ipv4.ip_local_port_range,
// 32768-60999 by default), so the kernel never hands this port to some other
// process as an auto-assigned source port and fails our bind spuriously. It sits
// next to the canonical testability port to read as one, while staying distinct
// so a tc8-dut a developer has running does not collide with the gate — an
// invariant the static_assert below keeps true rather than merely asserting in
// prose. A second concurrent gate run does not silently share this port: the
// endpoint's control socket deliberately omits SO_REUSEADDR (see
// ProtocolServer::bindControl), so the duplicate bind fails and start() returns
// false — loud, not a split brain.
constexpr std::uint16_t kConsumerPort = 30707;
static_assert(kConsumerPort != tc8::testability::kDefaultPort,
              "the gate's port must differ from the canonical deployment port");

class OemModule : public tc8::testability::MiddlewareModule {
public:
    std::vector<std::uint8_t> groups() const override { return {kOemGroupHigh}; }
    void onStart(tc8::testability::MiddlewareContext &) override {}
    void onStop() override {}
    void onPrimitive(const tc8::testability::Header &header, const std::uint8_t *dat,
                     std::size_t dat_len, const tc8::net::Endpoint &, std::uint8_t &rid,
                     std::vector<std::uint8_t> &resp_dat) override {
        // pidOf(): the codec SSOT owns the (EVB<<15)|(GID<<8)|PID layout — a module
        // never re-derives it by hand.
        if (tc8::testability::pidOf(header.method_id) != kOemPidReverse) {
            rid = tc8::testability::kRidENtf;
            return;
        }
        resp_dat.assign(dat, dat + dat_len);
        std::reverse(resp_dat.begin(), resp_dat.end());
        rid = tc8::testability::kRidEOk;
    }
};

// Drive the registered OEM module the way a tester does: a request through the
// exported client, over the loopback wire, into the module's handler and back.
bool driveOemModuleOverTheWire() {
    tc8::testability::TestabilityConfig cfg;
    cfg.dut_ip_be = ::htonl(INADDR_LOOPBACK);
    cfg.dut_port = kConsumerPort;

    // A standard GENERAL primitive first (PRS_TPSP §6.10 GET_VERSION), through the
    // exported typed wrapper: the endpoint's own built-in groups must answer an
    // out-of-tree client, not just the OEM extension.
    const auto version = tc8::testability::testabilityGetVersion(cfg);
    if (!version) {
        std::fprintf(stderr, "oem-utm-consumer: GET_VERSION got no response from the endpoint\n");
        return false;
    }

    // Then the OEM group, through the generic testabilityCall engine — the seam an
    // OEM's own typed wrappers build on, and the one the built-in wrappers cannot
    // reach because the group is non-standard by construction.
    const std::vector<std::uint8_t> req{0xA1, 0xB2, 0xC3};
    const std::vector<std::uint8_t> want{0xC3, 0xB2, 0xA1};
    const auto resp = tc8::testability::testabilityCall(cfg, kOemGroupHigh, kOemPidReverse, req);
    if (!resp.eok()) {
        std::fprintf(stderr,
                     "oem-utm-consumer: OEM primitive did not return E_OK "
                     "(ok=%d rid=0x%02X)\n",
                     static_cast<int>(resp.ok), static_cast<unsigned>(resp.rid));
        return false;
    }
    if (resp.dat != want) {
        std::fprintf(stderr,
                     "oem-utm-consumer: OEM primitive returned %zu unexpected byte(s) — "
                     "the module's handler did not produce the response\n",
                     resp.dat.size());
        return false;
    }
    std::printf(
        "oem-utm-consumer: endpoint reports testability v%u.%u.%u; OEM group 0x%02X "
        "answered over the wire\n",
        static_cast<unsigned>(version->major), static_cast<unsigned>(version->minor),
        static_cast<unsigned>(version->patch), static_cast<unsigned>(kOemGroupHigh));
    return true;
}

}  // namespace

int main() {
    tc8::testability::ProtocolServer server{std::make_unique<tc8::dut::PosixSocketBackend>()};
    server.registerModule(std::make_unique<OemModule>());
    if (!server.start(kConsumerPort)) {
        std::fprintf(stderr, "oem-utm-consumer: could not bind the endpoint on port %u\n",
                     kConsumerPort);
        return 1;
    }

    const bool wire_ok = driveOemModuleOverTheWire();
    server.stop();
    if (!wire_ok) {
        return 1;
    }

    // Exercise the exported AUTOSAR engines so the find_package surface covers
    // them, not just the seam. A real OEM module composes these with proprietary
    // keys and config; here the inputs are placeholder zeros (no OEM content).
    // Deriving the exit code from both keeps the calls from being stripped.
    const std::array<std::uint8_t, 16> key{};
    const std::array<std::uint8_t, 16> tag =
        tc8::crypto::aesCmac(key.data(), key.size(), nullptr, 0);

    const tc8::pn::PnFilter filter{tc8::pn::PnConfig{0, 1}};
    const std::vector<std::uint8_t> pdu{0x00};
    const bool relevant = filter.relevant(pdu.data(), pdu.size(), {0x00});

    const std::uint8_t crc8 = tc8::crc::crc8SaeJ1850(pdu.data(), pdu.size(), 0x00, true);
    const std::uint16_t crc16 = tc8::crc::crc16Ccitt(pdu.data(), pdu.size(), 0x0000, true);

    std::vector<std::uint8_t> e2ePdu(8, 0x00);
    tc8::e2e::Profile05Protector e2e{tc8::e2e::Profile05Config{0x0000, 0, 1}};
    e2e.protect(e2ePdu.data(), e2ePdu.size());

    tc8::com::SignalEngine com{{tc8::com::PduDef{
        1, 1, {tc8::com::SignalDef{1, 0, 4, tc8::com::Endianness::kLittle}}}}};
    com.setSignal(1, 0);
    const std::vector<std::uint8_t> comPdu = com.packPdu(1);

    tc8::nm::StateMachine nm{
        tc8::nm::Timing{std::chrono::milliseconds{500}, std::chrono::milliseconds{2000},
                        std::chrono::milliseconds{1000}, std::chrono::milliseconds{1500}},
        tc8::nm::PduLayout{8, 0, 1, 2, 6}, 0};
    nm.requestNetwork();
    const std::vector<std::uint8_t> nmPdu = nm.buildPdu();

    tc8::someiptp::Segmenter someipTp{16};
    const auto someipSegs =
        someipTp.segment(tc8::someiptp::MessageHeader{}, pdu.data(), pdu.size());

    // Observe every engine's result through a volatile sink so the out-of-tree
    // link genuinely depends on each exported lib (a dropped engine then fails
    // to link) without asserting any value here — that is the unit tests' job.
    volatile std::uint32_t sink = tag[0];
    sink ^= static_cast<std::uint32_t>(relevant ? 1U : 0U);
    sink ^= static_cast<std::uint32_t>(crc8);
    sink ^= static_cast<std::uint32_t>(crc16);
    sink ^= static_cast<std::uint32_t>(e2ePdu[2]);
    sink ^= static_cast<std::uint32_t>(comPdu[0]);
    sink ^= static_cast<std::uint32_t>(nmPdu[0]);
    sink ^= static_cast<std::uint32_t>(someipSegs.empty() ? 0U : someipSegs[0][0]);
    (void)sink;
    return 0;
}
