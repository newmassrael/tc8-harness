#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

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

// The 6-byte Ethernet hardware (MAC) address of `iface_name`, or std::nullopt
// when the interface does not exist or the SIOCGIFHWADDR query fails. Sibling
// of `ipv4OfInterface` for stimulus that must advertise the tester's REAL
// interface MAC on the wire — e.g. an ARP responder armed for a tester-spoofed
// source IP, where the DUT's unicast Response must be addressed to a MAC the
// tester actually receives on (rather than a synthetic one that depends on
// promiscuous capture). Header-only — a single ioctl on a throwaway socket —
// so every stimulus translation unit shares one definition.
//
// A successful query on a loopback-class interface yields the all-zero address
// (`lo` has no Ethernet MAC); that is reported as a value, not nullopt, because
// the ioctl succeeded. Callers that require an Ethernet MAC validate the
// interface class themselves rather than overloading the zero address as a
// failure sentinel.
inline std::optional<std::array<std::uint8_t, 6>> macOfInterface(std::string_view iface_name) {
    if (iface_name.empty() || iface_name.size() >= IFNAMSIZ) {
        return std::nullopt;
    }
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return std::nullopt;
    }
    ifreq ifr{};
    // string_view is not guaranteed NUL-terminated; copy the bounded name and
    // terminate explicitly (the size < IFNAMSIZ guard leaves room for the NUL).
    std::memcpy(ifr.ifr_name, iface_name.data(), iface_name.size());
    ifr.ifr_name[iface_name.size()] = '\0';
    std::optional<std::array<std::uint8_t, 6>> result;
    if (::ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
        std::array<std::uint8_t, 6> mac{};
        std::memcpy(mac.data(), ifr.ifr_hwaddr.sa_data, mac.size());
        result = mac;
    }
    ::close(sock);
    return result;
}

}  // namespace tc8::stimulus
