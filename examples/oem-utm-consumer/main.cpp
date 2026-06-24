// Out-of-tree consumer of the tc8-utm SDK — the shape a separate, private OEM
// repository takes: include the installed public headers, host a ProtocolServer
// on the POSIX backend, and attach an OEM service-group MiddlewareModule. This
// is a build/link smoke (the server is not started — no network here); it proves
// the exported find_package(tc8-utm) surface compiles and links out-of-tree.

#include <cstdint>
#include <memory>
#include <vector>

#include "posix_socket_backend.h"
#include "testability/middleware.h"
#include "testability/protocol_server.h"

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
    return 0;
}
