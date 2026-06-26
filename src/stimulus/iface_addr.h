#pragma once

#include <cstdint>
#include <string_view>

#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace tc8::stimulus {

// The IPv4 address (network byte order) assigned to `iface_name`, or 0 if the
// interface has no IPv4 address (or does not exist). Shared by the UDP emit
// helpers and the SD/RPC builders so a stimulus binds to the intended leg of a
// veth pair instead of relying on the default route. Header-only (the body is a
// single getifaddrs scan) so every stimulus translation unit shares one
// definition rather than re-deriving its own.
inline std::uint32_t ipv4OfInterface(std::string_view iface_name) {
    ifaddrs *head = nullptr;
    if (getifaddrs(&head) != 0 || head == nullptr) {
        return 0;
    }
    std::uint32_t addr = 0;
    for (ifaddrs *a = head; a != nullptr; a = a->ifa_next) {
        if (a->ifa_addr == nullptr || a->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if (a->ifa_name != nullptr && iface_name == a->ifa_name) {
            addr = reinterpret_cast<sockaddr_in *>(a->ifa_addr)->sin_addr.s_addr;
            break;
        }
    }
    freeifaddrs(head);
    return addr;
}

}  // namespace tc8::stimulus
