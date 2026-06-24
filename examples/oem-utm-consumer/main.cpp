// Out-of-tree consumer of the tc8-utm SDK — the shape a separate, private OEM
// repository takes: include the installed public headers, host a ProtocolServer
// on the POSIX backend, attach an OEM service-group MiddlewareModule, and compose
// the exported AUTOSAR engines. This is a build/link smoke (the server is not
// started — no network here); it proves the exported find_package(tc8-utm)
// surface — seam plus every engine — compiles and links out-of-tree.

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "posix_socket_backend.h"
#include "testability/middleware.h"
#include "testability/protocol_server.h"
#include "autosar/aes_cmac.h"
#include "autosar/pn_filter.h"
#include "autosar/crc.h"

namespace {

// A minimal OEM group (PRS_TPSP §6.6: non-standard groups count down from 0x7F).
// A real OEM module would compose the AUTOSAR engines + its proprietary config;
// here it just answers "not found" so the example needs no OEM content.
constexpr std::uint8_t kOemGroupHigh = 0x7F;

class OemModule : public tc8::testability::MiddlewareModule {
public:
    std::vector<std::uint8_t> groups() const override { return {kOemGroupHigh}; }
    void onStart(tc8::testability::MiddlewareContext &) override {}
    void onStop() override {}
    void onPrimitive(const tc8::testability::Header &, const std::uint8_t *, std::size_t,
                     const tc8::net::Endpoint &, std::uint8_t &rid,
                     std::vector<std::uint8_t> &) override {
        rid = tc8::testability::kRidENtf;
    }
};

}  // namespace

int main() {
    tc8::testability::ProtocolServer server{std::make_unique<tc8::dut::PosixSocketBackend>()};
    server.registerModule(std::make_unique<OemModule>());

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

    const std::uint8_t crc8 = tc8::crc::crc8SaeJ1850(pdu.data(), pdu.size());
    const std::uint16_t crc16 = tc8::crc::crc16Ccitt(pdu.data(), pdu.size());

    // Observe every engine's result through a volatile sink so the out-of-tree
    // link genuinely depends on each exported lib (a dropped engine then fails
    // to link) without asserting any value here — that is the unit tests' job.
    volatile std::uint32_t sink = tag[0];
    sink ^= static_cast<std::uint32_t>(relevant ? 1U : 0U);
    sink ^= static_cast<std::uint32_t>(crc8);
    sink ^= static_cast<std::uint32_t>(crc16);
    (void)sink;
    return 0;
}
