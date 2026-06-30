#include "cli/expect_parser.h"

#include <arpa/inet.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <string>
#include <string_view>
#include <type_traits>

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

// --- Generated `--expect` key tables (SSOT: src/cli/tc8_expect_keys.def) -----
//
// The accepted key set, each key's value kind, and each group's `--expect`
// namespace prefix all live in tc8_expect_keys.def. Every overload below
// builds its lookup table by expanding that file, so the parser cannot accept
// an unlisted key nor silently drop a listed one. The setter dereferences the
// target member by its real type, so a row whose `kind` disagrees with the
// member type is a compile error. See docs/tech-debt.md TD-03.
namespace {

// Value kinds. U24 (SD TTL) and U32 members are both uint32; the kind only
// narrows the accepted numeric range.
enum class EKind { U8, U16, U24, U32, IPV4, MAC };

constexpr std::uint64_t ekindMax(EKind k) {
    switch (k) {
        case EKind::U8:  return 0xFFull;
        case EKind::U16: return 0xFFFFull;
        case EKind::U24: return 0xFFFFFFull;
        case EKind::U32: return 0xFFFFFFFFull;
        default:         return 0;  // IPV4/MAC are not range-checked numerically
    }
}

constexpr std::size_t ekindStorage(EKind k) {
    switch (k) {
        case EKind::U8:  return 1;
        case EKind::U16: return 2;
        case EKind::U24: return 4;  // stored in a uint32 member
        case EKind::U32: return 4;
        default:         return 0;
    }
}

// Parse `v` per kind `K` and assign into `member` (its real type). The
// static_asserts pin the kind's value CLASS to the member type at compile time
// (IPV4→uint32, MAC→array<6>, numeric→unsigned of the matching width), so e.g.
// a U16 row on a uint32 member fails to compile. The one distinction they do
// NOT catch is U24 vs U32 (both target uint32, differing only in range): a
// U24↔U32 mislabel compiles, and its range is instead enforced by parseNumeric
// + ekindMax and pinned by expect_parser_test's RejectsOverflowTtl24Bit.
template <EKind K, class M>
bool applyField(std::string_view v, M &member) {
    if constexpr (K == EKind::IPV4) {
        static_assert(std::is_same_v<M, std::uint32_t>,
                      "IPV4 key must target a uint32 (network byte order) member");
        std::uint32_t ip = 0;
        if (!parseIpv4Dotted(v, ip)) {
            return false;
        }
        member = ip;
        return true;
    } else if constexpr (K == EKind::MAC) {
        static_assert(std::is_same_v<M, std::array<std::uint8_t, 6>>,
                      "MAC key must target a std::array<uint8_t, 6> member");
        return parseMac(v, member);
    } else {
        static_assert(std::is_integral_v<M> && std::is_unsigned_v<M>,
                      "numeric key must target an unsigned integral member");
        static_assert(sizeof(M) == ekindStorage(K),
                      "numeric key kind width does not match member size");
        std::uint64_t n = 0;
        if (!parseNumeric(v, n) || n > ekindMax(K)) {
            return false;
        }
        member = static_cast<M>(n);
        return true;
    }
}

// The colon-separated hex byte list — fills two members, so it is handled
// outside the single-member applyField setter.
bool applyPayload(std::string_view val, ::tc8::SomeIpExpectations &e) {
    if (val.empty()) {
        return false;
    }
    std::array<std::uint8_t, ::tc8::kMaxExpectedPayload> bytes{};
    std::uint32_t len = 0;
    std::size_t cursor = 0;
    while (true) {
        const std::size_t colon = val.find(':', cursor);
        const std::size_t end = (colon == std::string_view::npos) ? val.size() : colon;
        std::uint8_t b = 0;
        if (len >= bytes.size() || !parseHexOctet(val.substr(cursor, end - cursor), b)) {
            return false;
        }
        bytes[len++] = b;
        if (colon == std::string_view::npos) {
            break;
        }
        cursor = colon + 1;
    }
    e.payload = bytes;
    e.payload_len = len;
    return true;
}

// One row of a group's key table: the key string and a type-safe setter bound
// to the group's expectation type T. Each table is monomorphic in T (built
// inside one overload), so the setter takes `T&` directly — no `void*`
// erasure, hence no unchecked cast.
template <class T>
struct EKey {
    std::string_view name;
    bool (*apply)(T &e, std::string_view v);
};

// Build one table row: a key string + a non-capturing setter that parses per
// `kind` into `e.name` (its real type, so applyField's static_asserts pin
// kind↔type). Written once; each overload maps its group's .def sub-macro to
// it, so the row shape is not copy-pasted per group.
#define TC8_EK_ROW(T, kind, name)                                         \
    EKey<::tc8::T>{#name, [](::tc8::T &ctx, std::string_view v) {          \
                       return applyField<EKind::kind>(v, ctx.name);       \
                   }},
// The payload key fills two members, so it routes to applyPayload(ctx) instead
// of a single-member setter.
#define TC8_EKP_ROW(T, name)                                              \
    EKey<::tc8::T>{#name, [](::tc8::T &ctx, std::string_view v) {          \
                       return applyPayload(v, ctx);                       \
                   }},

// Strip `prefix`, split `key=value`, look the key up in `table`, apply it.
// Returns true only when the key is recognised AND its value parsed; a missing
// prefix, missing '=', unknown key, or bad value all return false (the caller
// chains the protocol-scoped overloads and reports one error if all decline).
template <class T>
bool matchExpect(std::string_view token, std::string_view prefix, T &e,
                 const EKey<T> *table, std::size_t count) {
    if (token.substr(0, prefix.size()) != prefix) {
        return false;
    }
    const std::string_view body = token.substr(prefix.size());
    const auto eq = body.find('=');
    if (eq == std::string_view::npos) {
        return false;
    }
    const std::string_view key = body.substr(0, eq);
    const std::string_view val = body.substr(eq + 1);
    for (std::size_t i = 0; i < count; ++i) {
        if (key == table[i].name) {
            return table[i].apply(e, val);
        }
    }
    return false;
}

// Per-group `--expect` namespace prefixes, generated from the .def GROUP rows.
#define TC8_EXPECT_GROUP(group, prefix) constexpr std::string_view ekPrefix_##group = prefix;
#include "cli/tc8_expect_keys.def"
#undef TC8_EXPECT_GROUP

}  // namespace

// Each overload builds its lookup table by expanding tc8_expect_keys.def with
// its own group's sub-macro; every other group's rows default to empty.
bool applyExpectToken(std::string_view token, ::tc8::SomeIpExpectations &e) {
    static constexpr EKey<::tc8::SomeIpExpectations> kKeys[] = {
#define TC8_EK_someip(kind, name) TC8_EK_ROW(SomeIpExpectations, kind, name)
#define TC8_EKP_someip(name)      TC8_EKP_ROW(SomeIpExpectations, name)
#include "cli/tc8_expect_keys.def"
#undef TC8_EK_someip
#undef TC8_EKP_someip
    };
    return matchExpect(token, ekPrefix_someip, e, kKeys, std::size(kKeys));
}

bool applyExpectToken(std::string_view token, ::tc8::ArpExpectations &e) {
    static constexpr EKey<::tc8::ArpExpectations> kKeys[] = {
#define TC8_EK_arp(kind, name) TC8_EK_ROW(ArpExpectations, kind, name)
#include "cli/tc8_expect_keys.def"
#undef TC8_EK_arp
    };
    return matchExpect(token, ekPrefix_arp, e, kKeys, std::size(kKeys));
}

bool applyExpectToken(std::string_view token, ::tc8::DutIdentity &e) {
    static constexpr EKey<::tc8::DutIdentity> kKeys[] = {
#define TC8_EK_dut(kind, name) TC8_EK_ROW(DutIdentity, kind, name)
#include "cli/tc8_expect_keys.def"
#undef TC8_EK_dut
    };
    return matchExpect(token, ekPrefix_dut, e, kKeys, std::size(kKeys));
}

bool applyExpectToken(std::string_view token, ::tc8::ArpStimulusConfig &e) {
    static constexpr EKey<::tc8::ArpStimulusConfig> kKeys[] = {
#define TC8_EK_arp_stimulus(kind, name) TC8_EK_ROW(ArpStimulusConfig, kind, name)
#include "cli/tc8_expect_keys.def"
#undef TC8_EK_arp_stimulus
    };
    return matchExpect(token, ekPrefix_arp_stimulus, e, kKeys, std::size(kKeys));
}

bool applyExpectToken(std::string_view token, ::tc8::Icmpv4Expectations &e) {
    static constexpr EKey<::tc8::Icmpv4Expectations> kKeys[] = {
#define TC8_EK_icmpv4(kind, name) TC8_EK_ROW(Icmpv4Expectations, kind, name)
#include "cli/tc8_expect_keys.def"
#undef TC8_EK_icmpv4
    };
    return matchExpect(token, ekPrefix_icmpv4, e, kKeys, std::size(kKeys));
}

bool applyExpectToken(std::string_view token, ::tc8::Ipv4Expectations &e) {
    static constexpr EKey<::tc8::Ipv4Expectations> kKeys[] = {
#define TC8_EK_ipv4(kind, name) TC8_EK_ROW(Ipv4Expectations, kind, name)
#include "cli/tc8_expect_keys.def"
#undef TC8_EK_ipv4
    };
    return matchExpect(token, ekPrefix_ipv4, e, kKeys, std::size(kKeys));
}

bool applyExpectToken(std::string_view token, ::tc8::Dhcpv4Expectations &e) {
    static constexpr EKey<::tc8::Dhcpv4Expectations> kKeys[] = {
#define TC8_EK_dhcpv4(kind, name) TC8_EK_ROW(Dhcpv4Expectations, kind, name)
#include "cli/tc8_expect_keys.def"
#undef TC8_EK_dhcpv4
    };
    return matchExpect(token, ekPrefix_dhcpv4, e, kKeys, std::size(kKeys));
}

#undef TC8_EK_ROW
#undef TC8_EKP_ROW

}  // namespace tc8::cli
