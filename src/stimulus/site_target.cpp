#include "stimulus/site_target.h"

namespace tc8::stimulus {
namespace {

// Not atomic on purpose. It is written once by the runner before any stimulus
// runs and only read afterwards, so there is no concurrent write to order
// against; making it atomic would suggest a race that the call sequence
// forbids. Parallel RUNS are separate processes (the orchestrator forks a
// harness per case), not threads sharing this.
std::uint32_t g_site_dut_ipv4 = 0;

}  // namespace

void setSiteDutIpv4(std::uint32_t ipv4_be) {
    g_site_dut_ipv4 = ipv4_be;
}

std::uint32_t siteDutIpv4() {
    return g_site_dut_ipv4;
}

}  // namespace tc8::stimulus
