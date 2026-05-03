#include <cstdint>

#include <gtest/gtest.h>

#include "sce_integration/ipv4_captured.h"
#include "tc8/protocol_frames/ipv4_frame.h"

namespace tc8 {
namespace {

// Regression guard on the data-transformation helper the §4.4 pilot
// relies on. The packet_pipeline emits an `Ipv4Frame` with all 12
// RFC 791 fields populated from libtins and (optionally) a pointer at
// the options byte range; `fillIpv4CapturedFromFrame` copies the scalar
// fields into the SCE Named Context struct the SCXML guards read. Any
// later refactor that drops a field or drifts a byte order silently
// turns a positive test into a false pass, so the expected behaviour
// is pinned here.
//
// Address fields are in network byte order — same convention as
// `Icmpv4Captured::src_ip` and as the `parseIpv4Dotted` CLI parser —
// so the SCXML guard `captured.src_addr == expected.dut_iface_ip`
// compares two NBO uint32s without a swap.
TEST(FillIpv4Captured, CopiesAllScalarFields) {
    Ipv4Frame frame{};
    frame.version         = 4;
    frame.ihl             = 5;
    frame.tos             = 0xAB;
    frame.total_length    = 576;
    frame.identification  = 0xBEEF;
    frame.flags           = 0x2;            // DF set, MF clear, reserved clear
    frame.fragment_offset = 0x0000;
    frame.ttl             = 64;
    frame.protocol        = 1;              // ICMP
    frame.header_checksum = 0xC0DE;
    frame.src_addr        = 0x010010AC;     // 172.16.0.1 (NBO on LE host)
    frame.dst_addr        = 0x020010AC;     // 172.16.0.2

    Ipv4Captured captured{};
    fillIpv4CapturedFromFrame(captured, frame);

    EXPECT_EQ(captured.version,         4u);
    EXPECT_EQ(captured.ihl,             5u);
    EXPECT_EQ(captured.tos,             0xABu);
    EXPECT_EQ(captured.total_length,    576u);
    EXPECT_EQ(captured.identification,  0xBEEFu);
    EXPECT_EQ(captured.flags,           0x2u);
    EXPECT_EQ(captured.fragment_offset, 0u);
    EXPECT_EQ(captured.ttl,             64u);
    EXPECT_EQ(captured.protocol,        1u);
    EXPECT_EQ(captured.header_checksum, 0xC0DEu);
    EXPECT_EQ(captured.src_addr,        0x010010ACu);
    EXPECT_EQ(captured.dst_addr,        0x020010ACu);
}

TEST(FillIpv4Captured, OverwritesPriorContents) {
    // The same captured slot is reused across multiple events in a
    // single case run (both the tester's own IPv4 frame and the DUT's
    // reply flow through the SM). A stale field from an earlier event
    // must not survive into the next guard evaluation.
    Ipv4Captured captured{};
    captured.version      = 6;
    captured.total_length = 0xFFFF;
    captured.src_addr     = 0xDEADBEEF;

    Ipv4Frame frame{};
    frame.version      = 4;
    frame.total_length = 48;
    frame.src_addr     = 0x010010AC;
    fillIpv4CapturedFromFrame(captured, frame);

    EXPECT_EQ(captured.version,      4u);
    EXPECT_EQ(captured.total_length, 48u);
    EXPECT_EQ(captured.src_addr,     0x010010ACu);
}

TEST(HeaderChecksumValid, AcceptsKnownGoodHeader) {
    // Hand-computed good checksum over the header below (RFC 1071,
    // checksum field treated as 0 during compute, final ~sum yields
    // 0xE285). The method's self-check is that the running sum over
    // all bytes INCLUDING the stored checksum equals 0xFFFF (one's-
    // complement zero).
    Ipv4Captured c{};
    c.version         = 4;
    c.ihl             = 5;
    c.tos             = 0;
    c.total_length    = 0x54;
    c.identification  = 0;
    c.flags           = 0x2;
    c.fragment_offset = 0;
    c.ttl             = 64;
    c.protocol        = 1;
    c.header_checksum = 0xE285;
    c.src_addr        = 0x010010AC;   // 172.16.0.1 NBO
    c.dst_addr        = 0x020010AC;   // 172.16.0.2 NBO
    EXPECT_TRUE(c.header_checksum_valid());
}

TEST(HeaderChecksumValid, RejectsOneBitFlip) {
    // Same header as above but one bit flipped in the checksum field.
    // RFC 1071 validation must notice — this is exactly the DUT-reply
    // discrimination property §4.4.4.2 CHECKSUM_05 asserts.
    Ipv4Captured c{};
    c.version         = 4;
    c.ihl             = 5;
    c.total_length    = 0x54;
    c.flags           = 0x2;
    c.ttl             = 64;
    c.protocol        = 1;
    c.header_checksum = 0xE284;   // correct was 0xE285
    c.src_addr        = 0x010010AC;
    c.dst_addr        = 0x020010AC;
    EXPECT_FALSE(c.header_checksum_valid());
}

TEST(HeaderChecksumValid, RejectsWrongSourceAddress) {
    // Flip one byte of src_addr — a conformant receiver would reject
    // this packet. The method must notice without needing the
    // checksum field to be touched.
    Ipv4Captured c{};
    c.version         = 4;
    c.ihl             = 5;
    c.total_length    = 0x54;
    c.flags           = 0x2;
    c.ttl             = 64;
    c.protocol        = 1;
    c.header_checksum = 0xE285;
    c.src_addr        = 0x010010AD;   // 172.16.0.1 → 172.16.0.1 + 1 bit
    c.dst_addr        = 0x020010AC;
    EXPECT_FALSE(c.header_checksum_valid());
}

TEST(HeaderChecksumValid, RejectsIhlNotFive) {
    // The pilot scope is no-options headers (IHL=5); a DUT that
    // replied with options would need the §4.4.4.5 OPTIONS work to
    // supply the raw options bytes. Until then, any IHL != 5 is a
    // coverage gap we announce via false rather than silently
    // assuming the options are zero.
    Ipv4Captured c{};
    c.version         = 4;
    c.ihl             = 6;
    c.total_length    = 0x58;
    c.ttl             = 64;
    c.protocol        = 1;
    c.header_checksum = 0xAAAA;
    EXPECT_FALSE(c.header_checksum_valid());
}

TEST(FillIpv4Captured, MinimumHeaderShape) {
    // RFC 791 minimum-shape frame: version=4, IHL=5 (20 B no options),
    // total_length=20 (header only). HEADER_01's positive guard reads
    // `captured.total_length >= 20`; this boundary input pins the
    // comparison that the pilot SCXML relies on.
    Ipv4Frame frame{};
    frame.version      = 4;
    frame.ihl          = 5;
    frame.total_length = 20;

    Ipv4Captured captured{};
    fillIpv4CapturedFromFrame(captured, frame);

    EXPECT_EQ(captured.ihl,          5u);
    EXPECT_EQ(captured.total_length, 20u);
    EXPECT_GE(captured.total_length, 20u);
}

}  // namespace
}  // namespace tc8
