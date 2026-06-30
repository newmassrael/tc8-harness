#include <array>
#include <cstdint>

#include <gtest/gtest.h>

#include "sce_integration/dhcpv4_wire.h"

namespace tc8 {
namespace {

// Pins the C++ side of the DHCPv4 BOOTP fixed-header SSOT
// (src/sce_integration/dhcpv4_wire.def, TD-02) bit-for-bit. The decoder
// here and the Python site mirror both expand the same .def, so a wrong
// offset/width would be applied to both consistently; this test plus the
// generator's golden-vector self-test (tools/gen_dhcpv4_wire.py) together
// catch a wrong number in the .def itself. See docs/tech-debt.md TD-02.

// Build a DHCPDISCOVER-shaped BOOTP body: 240 B fixed part + magic cookie.
// Every fixed field carries a DISTINCT nonzero value (matching the generator's
// golden vector) so a wrong offset cannot alias another field's value or a zero
// run and still pass.
std::array<std::uint8_t, 240> makeBootp() {
    std::array<std::uint8_t, 240> b{};
    b[0] = 1;   // op = BOOTREQUEST
    b[1] = 1;   // htype = Ethernet
    b[2] = 6;   // hlen
    b[3] = 2;   // hops (distinct nonzero)
    b[4] = 0x12; b[5] = 0x34; b[6] = 0x56; b[7] = 0x78;  // xid
    b[8] = 0x01; b[9] = 0x02;                            // secs (distinct nonzero)
    b[10] = 0x80; b[11] = 0x00;                          // flags = BROADCAST
    b[12] = 10;  b[13] = 1;  b[14] = 2;  b[15] = 3;      // ciaddr 10.1.2.3
    b[16] = 172; b[17] = 16; b[18] = 0;  b[19] = 5;      // yiaddr 172.16.0.5
    b[20] = 192; b[21] = 168; b[22] = 7; b[23] = 9;      // siaddr 192.168.7.9
    b[24] = 169; b[25] = 254; b[26] = 11; b[27] = 22;    // giaddr 169.254.11.22
    b[28] = 0xAA; b[29] = 0xBB; b[30] = 0xCC;
    b[31] = 0xDD; b[32] = 0xEE; b[33] = 0xFF;            // chaddr MAC
    b[236] = 0x63; b[237] = 0x82; b[238] = 0x53; b[239] = 0x63;  // cookie
    return b;
}

TEST(Dhcpv4Wire, DecodesBootpFixedHeader) {
    const auto b = makeBootp();
    Dhcpv4Frame df{};
    dhcpv4_wire::decodeBootpFixedHeader(b.data(), df);

    EXPECT_EQ(df.op, 1u);
    EXPECT_EQ(df.htype, 1u);
    EXPECT_EQ(df.hlen, 6u);
    EXPECT_EQ(df.hops, 2u);
    EXPECT_EQ(df.xid, 0x12345678u);
    EXPECT_EQ(df.secs, 0x0102u);
    EXPECT_EQ(df.flags, 0x8000u);
    // Addresses stay network byte order: e.g. 10.1.2.3 -> bytes 0A 01 02 03,
    // which on a little-endian host reads back as 0x0302010A (same convention
    // as ipv4_decode_test / parseIpv4Dotted). Each address distinct so a
    // swapped offset is caught.
    EXPECT_EQ(df.ciaddr, 0x0302010Au);  // 10.1.2.3
    EXPECT_EQ(df.yiaddr, 0x050010ACu);  // 172.16.0.5
    EXPECT_EQ(df.siaddr, 0x0907A8C0u);  // 192.168.7.9
    EXPECT_EQ(df.giaddr, 0x160BFEA9u);  // 169.254.11.22
    // chaddr keeps all 16 BOOTP bytes; only the first hlen are the MAC.
    EXPECT_EQ(df.chaddr[0], 0xAAu);
    EXPECT_EQ(df.chaddr[5], 0xFFu);
    EXPECT_EQ(df.chaddr[6], 0x00u);
}

TEST(Dhcpv4Wire, ValidatesMagicCookie) {
    auto b = makeBootp();
    EXPECT_TRUE(dhcpv4_wire::magicCookieValid(b.data()));
    b[238] = 0x00;  // corrupt one cookie byte
    EXPECT_FALSE(dhcpv4_wire::magicCookieValid(b.data()));
}

TEST(Dhcpv4Wire, ConstantsMatchRfc) {
    EXPECT_EQ(dhcpv4_wire::kMagicCookieOff, 236u);
    EXPECT_EQ(dhcpv4_wire::kMagicCookie, 0x63825363u);
    EXPECT_EQ(dhcpv4_wire::kOptionsOff, 240u);
}

}  // namespace
}  // namespace tc8
