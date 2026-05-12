#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace tc8::iface_enum {

struct IfaceInfo {
    std::string                  name;
    std::array<std::uint8_t, 6>  mac{};
    std::uint32_t                ip_be    = 0;
    std::uint32_t                bcast_be = 0;
};

// Drop duplicate IfaceInfo entries that share a name, keeping the
// first-seen occurrence. Linux's getifaddrs(3) returns one entry per
// AF_INET address — an iface with multiple IPv4 addresses (e.g.
// `setup-netns.sh`'s UI_07/_08 alias 172.16.0.5 stacked on top of the
// primary 172.16.0.2) shows up twice in the raw enumeration. Without
// dedupe, `UpperTesterServer::start()` would build
// `dhcpv4_clients_[1]` against the same iface as
// `dhcpv4_clients_[0]` and §4.7.6.5 USAGE_01 would observe two
// DHCPDISCOVERs with one shared chaddr (RFC 2131 §3.6 MUST violation
// — `fail:diface_0_and_diface_1_share_same_chaddr`). First-seen wins
// so the kernel's primary AF_INET (typically the first `ip addr add`)
// drives `iface_ip_be_` for the legacy §4.4 / §4.5 / §4.8 surface.
inline std::vector<IfaceInfo>
dedupeByName(std::vector<IfaceInfo> ifaces) {
    std::unordered_set<std::string> seen;
    seen.reserve(ifaces.size());
    std::vector<IfaceInfo> out;
    out.reserve(ifaces.size());
    for (auto& info : ifaces) {
        if (seen.insert(info.name).second) {
            out.push_back(std::move(info));
        }
    }
    return out;
}

}  // namespace tc8::iface_enum
