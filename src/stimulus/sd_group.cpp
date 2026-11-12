#include "stimulus/sd_group.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <atomic>
#include <cstdlib>

#include "tc8/dut_config.h"

namespace tc8::stimulus {
namespace {

// 0 = the run published no group.
std::atomic<std::uint32_t> g_sd_multicast_group_be{0};

// `tc8::dut::kSdMcastGroup` in network byte order. The literal is the harness's own
// constant, so a malformed one is a defect in this tree, not a run condition: it stops
// the process at the first read rather than handing every SD send a 0.0.0.0 group.
std::uint32_t compiledDefaultBe() {
    static const std::uint32_t value = [] {
        in_addr group{};
        if (::inet_pton(AF_INET, ::tc8::dut::kSdMcastGroup, &group) != 1) {
            std::abort();
        }
        return group.s_addr;
    }();
    return value;
}

}  // namespace

void setSdMulticastGroup(std::uint32_t group_be) {
    g_sd_multicast_group_be.store(group_be, std::memory_order_relaxed);
}

std::uint32_t sdMulticastGroupBe() {
    const std::uint32_t published = g_sd_multicast_group_be.load(std::memory_order_relaxed);
    return published != 0 ? published : compiledDefaultBe();
}

std::string sdMulticastGroup() {
    in_addr group{};
    group.s_addr = sdMulticastGroupBe();
    char buf[INET_ADDRSTRLEN] = {};
    ::inet_ntop(AF_INET, &group, buf, sizeof(buf));
    return std::string(buf);
}

}  // namespace tc8::stimulus
