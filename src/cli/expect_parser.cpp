#include "cli/expect_parser.h"

#include <arpa/inet.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

namespace tc8::cli {

bool parseNumeric(std::string_view text, std::uint64_t &out) {
    if (text.empty()) {
        return false;
    }
    std::string owned(text);
    char *end = nullptr;
    errno = 0;
    const unsigned long long v = std::strtoull(owned.c_str(), &end, 0);
    if (errno != 0 || end == owned.c_str() || *end != '\0') {
        return false;
    }
    out = static_cast<std::uint64_t>(v);
    return true;
}

bool parseIpv4Dotted(std::string_view text, std::uint32_t &out) {
    if (text.empty()) {
        return false;
    }
    const std::string owned(text);
    in_addr addr{};
    if (::inet_pton(AF_INET, owned.c_str(), &addr) != 1) {
        return false;
    }
    out = static_cast<std::uint32_t>(addr.s_addr);
    return true;
}

namespace {

bool parseHexOctet(std::string_view octet, std::uint8_t &out) {
    if (octet.empty() || octet.size() > 2) {
        return false;
    }
    std::uint8_t value = 0;
    for (char c : octet) {
        std::uint8_t digit = 0;
        if (c >= '0' && c <= '9') {
            digit = static_cast<std::uint8_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = static_cast<std::uint8_t>(10 + (c - 'a'));
        } else if (c >= 'A' && c <= 'F') {
            digit = static_cast<std::uint8_t>(10 + (c - 'A'));
        } else {
            return false;
        }
        value = static_cast<std::uint8_t>((value << 4) | digit);
    }
    out = value;
    return true;
}

}  // namespace

bool parseMac(std::string_view text, std::array<std::uint8_t, 6> &out) {
    std::array<std::uint8_t, 6> tmp{};
    std::size_t octet_idx = 0;
    std::size_t cursor = 0;
    while (cursor <= text.size() && octet_idx < tmp.size()) {
        const std::size_t next_colon = text.find(':', cursor);
        const std::size_t end = (next_colon == std::string_view::npos) ? text.size() : next_colon;
        if (!parseHexOctet(text.substr(cursor, end - cursor), tmp[octet_idx])) {
            return false;
        }
        ++octet_idx;
        if (next_colon == std::string_view::npos) {
            // Reached end-of-input — succeeds only if we filled all six.
            if (octet_idx != tmp.size()) {
                return false;
            }
            out = tmp;
            return true;
        }
        cursor = next_colon + 1;
    }
    return false;
}

bool applyExpectToken(std::string_view token, ::tc8::SomeIpExpectations &e) {
    const auto eq = token.find('=');
    if (eq == std::string_view::npos) {
        return false;
    }
    const std::string_view key = token.substr(0, eq);
    const std::string_view val = token.substr(eq + 1);

    // Endpoint-IP keys take a dotted-decimal value rather than a numeric
    // token, so they're parsed before the generic numeric branch (which
    // would reject `172.16.0.2` as malformed).
    if (key == "dut_iface_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.dut_iface_ip = ip;
        return true;
    }
    if (key == "sd_multicast_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.sd_multicast_ip = ip;
        return true;
    }
    if (key == "mcast_ipv4") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.mcast_ipv4 = ip;
        return true;
    }

    std::uint64_t n = 0;
    if (!parseNumeric(val, n)) {
        return false;
    }

    if (key == "service_id") {
        if (n > 0xFFFF) {
            return false;
        }
        e.service_id = static_cast<std::uint16_t>(n);
    } else if (key == "instance_id") {
        if (n > 0xFFFF) {
            return false;
        }
        e.instance_id = static_cast<std::uint16_t>(n);
    } else if (key == "major_version") {
        if (n > 0xFF) {
            return false;
        }
        e.major_version = static_cast<std::uint8_t>(n);
    } else if (key == "ttl") {
        if (n > 0xFFFFFF) {
            return false;  // SD TTL is 24-bit
        }
        e.ttl = static_cast<std::uint32_t>(n);
    } else if (key == "minor_version") {
        if (n > 0xFFFFFFFFu) {
            return false;
        }
        e.minor_version = static_cast<std::uint32_t>(n);
    } else if (key == "eventgroup_id") {
        if (n > 0xFFFF) {
            return false;
        }
        e.eventgroup_id = static_cast<std::uint16_t>(n);
    } else if (key == "udp_port") {
        if (n > 0xFFFF) {
            return false;
        }
        e.udp_port = static_cast<std::uint16_t>(n);
    } else if (key == "tcp_port") {
        if (n > 0xFFFF) {
            return false;
        }
        e.tcp_port = static_cast<std::uint16_t>(n);
    } else if (key == "mcast_port") {
        if (n > 0xFFFF) {
            return false;
        }
        e.mcast_port = static_cast<std::uint16_t>(n);
    } else {
        return false;
    }
    return true;
}

bool applyExpectToken(std::string_view token, ::tc8::ArpExpectations &e) {
    constexpr std::string_view kPrefix = "arp.";
    if (token.size() <= kPrefix.size() || token.substr(0, kPrefix.size()) != kPrefix) {
        return false;
    }
    const std::string_view body = token.substr(kPrefix.size());
    const auto eq = body.find('=');
    if (eq == std::string_view::npos) {
        return false;
    }
    const std::string_view key = body.substr(0, eq);
    const std::string_view val = body.substr(eq + 1);

    if (key == "dut_iface_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.dut_iface_ip = ip;
    } else if (key == "tester_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.tester_ip = ip;
    } else if (key == "dut_iface_mac") {
        std::array<std::uint8_t, 6> mac{};
        if (!parseMac(val, mac)) {
            return false;
        }
        e.dut_iface_mac = mac;
    } else if (key == "tester_mac") {
        std::array<std::uint8_t, 6> mac{};
        if (!parseMac(val, mac)) {
            return false;
        }
        e.tester_mac = mac;
    } else if (key == "dut_real_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.dut_real_ip = ip;
    } else if (key == "dut_real_mac") {
        std::array<std::uint8_t, 6> mac{};
        if (!parseMac(val, mac)) {
            return false;
        }
        e.dut_real_mac = mac;
    } else if (key == "tester_mac2") {
        std::array<std::uint8_t, 6> mac{};
        if (!parseMac(val, mac)) {
            return false;
        }
        e.tester_mac2 = mac;
    } else if (key == "tester_mac3") {
        std::array<std::uint8_t, 6> mac{};
        if (!parseMac(val, mac)) {
            return false;
        }
        e.tester_mac3 = mac;
    } else if (key == "tester_linklocal_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.tester_linklocal_ip = ip;
    } else if (key == "ut_cache_conditioning_s") {
        std::uint64_t n = 0;
        if (!parseNumeric(val, n) || n > 0xFFFF) {
            return false;
        }
        e.ut_cache_conditioning_s = static_cast<std::uint16_t>(n);
    } else {
        return false;
    }
    return true;
}

bool applyExpectToken(std::string_view token, ::tc8::Icmpv4Expectations &e) {
    constexpr std::string_view kPrefix = "icmpv4.";
    if (token.size() <= kPrefix.size() || token.substr(0, kPrefix.size()) != kPrefix) {
        return false;
    }
    const std::string_view body = token.substr(kPrefix.size());
    const auto eq = body.find('=');
    if (eq == std::string_view::npos) {
        return false;
    }
    const std::string_view key = body.substr(0, eq);
    const std::string_view val = body.substr(eq + 1);

    if (key == "tester_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.tester_ip = ip;
    } else if (key == "dut_iface_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.dut_iface_ip = ip;
    } else if (key == "echo_id") {
        std::uint64_t n = 0;
        if (!parseNumeric(val, n) || n > 0xFFFFu) {
            return false;
        }
        e.echo_id = static_cast<std::uint16_t>(n);
    } else if (key == "echo_seq") {
        std::uint64_t n = 0;
        if (!parseNumeric(val, n) || n > 0xFFFFu) {
            return false;
        }
        e.echo_seq = static_cast<std::uint16_t>(n);
    } else {
        return false;
    }
    return true;
}

bool applyExpectToken(std::string_view token, ::tc8::Ipv4Expectations &e) {
    constexpr std::string_view kPrefix = "ipv4.";
    if (token.size() <= kPrefix.size() || token.substr(0, kPrefix.size()) != kPrefix) {
        return false;
    }
    const std::string_view body = token.substr(kPrefix.size());
    const auto eq = body.find('=');
    if (eq == std::string_view::npos) {
        return false;
    }
    const std::string_view key = body.substr(0, eq);
    const std::string_view val = body.substr(eq + 1);

    if (key == "tester_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.tester_ip = ip;
    } else if (key == "dut_iface_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.dut_iface_ip = ip;
    } else if (key == "dut_alias_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.dut_alias_ip = ip;
    } else if (key == "tester_alias_ip") {
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(val, ip)) {
            return false;
        }
        e.tester_alias_ip = ip;
    } else {
        return false;
    }
    return true;
}

bool applyExpectToken(std::string_view token, ::tc8::Dhcpv4Expectations &e) {
    constexpr std::string_view kPrefix = "dhcpv4.";
    if (token.size() <= kPrefix.size() || token.substr(0, kPrefix.size()) != kPrefix) {
        return false;
    }
    const std::string_view body = token.substr(kPrefix.size());
    const auto eq = body.find('=');
    if (eq == std::string_view::npos) {
        return false;
    }
    const std::string_view key = body.substr(0, eq);
    const std::string_view val = body.substr(eq + 1);

    if (key == "dut_iface_mac") {
        std::array<std::uint8_t, 6> mac{};
        if (!parseMac(val, mac)) {
            return false;
        }
        e.dut_iface_mac = mac;
    } else {
        return false;
    }
    return true;
}

}  // namespace tc8::cli
