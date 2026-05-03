#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/someip_sd_builder.h"

namespace tc8::stimulus {
namespace {

// Deterministic input matching the tc8-dut defaults so failures in this
// test point directly at the wire-layout regression (byte-offset / endian
// / option-size) rather than at input churn.
SubscribeEventgroupParams makeRef() {
    SubscribeEventgroupParams p{};
    p.target.service_id = 0xF4E7;
    p.target.instance_id = 0x0001;
    p.target.eventgroup_id = 0x0042;
    p.target.major_version = 0x01;
    p.target.ttl = 3;
    p.target.counter = 0x0;
    // 172.16.0.3 in network byte order: 0xAC 0x10 0x00 0x03 → little-endian
    // uint32 0x030010AC since `ipv4_be` holds the four bytes already in
    // wire order (what `ifaddrs` hands back on little-endian Linux).
    p.tester_endpoint.ipv4_be = 0x030010AC;
    p.tester_endpoint.port = 0x8765;
    p.tester_endpoint.l4proto = 0x11;  // UDP
    p.session_id = 0x0001;
    p.sd_flags = 0xC0;
    return p;
}

TEST(BuildSubscribeEventgroup, TotalSizeIs56Bytes) {
    const auto bytes = buildSubscribeEventgroup(makeRef());
    EXPECT_EQ(bytes.size(), 56u);
}

TEST(BuildSubscribeEventgroup, SomeIpHeaderShape) {
    const auto b = buildSubscribeEventgroup(makeRef());
    ASSERT_GE(b.size(), 16u);
    // ServiceID = 0xFFFF, MethodID = 0x8100.
    EXPECT_EQ(b[0], 0xFFu);
    EXPECT_EQ(b[1], 0xFFu);
    EXPECT_EQ(b[2], 0x81u);
    EXPECT_EQ(b[3], 0x00u);
    // Length = 48 (8 request-id bytes + 40 payload bytes).
    EXPECT_EQ(b[4], 0x00u);
    EXPECT_EQ(b[5], 0x00u);
    EXPECT_EQ(b[6], 0x00u);
    EXPECT_EQ(b[7], 0x30u);
    // ClientID = 0, SessionID = 0x0001.
    EXPECT_EQ(b[8], 0x00u);
    EXPECT_EQ(b[9], 0x00u);
    EXPECT_EQ(b[10], 0x00u);
    EXPECT_EQ(b[11], 0x01u);
    // Proto=0x01, Iface=0x01, MsgType=0x02 (NOTIFICATION), ReturnCode=0.
    EXPECT_EQ(b[12], 0x01u);
    EXPECT_EQ(b[13], 0x01u);
    EXPECT_EQ(b[14], 0x02u);
    EXPECT_EQ(b[15], 0x00u);
}

TEST(BuildSubscribeEventgroup, SdFlagsAndLengths) {
    const auto b = buildSubscribeEventgroup(makeRef());
    ASSERT_GE(b.size(), 32u);
    // SD flags + 24-bit reserved.
    EXPECT_EQ(b[16], 0xC0u);
    EXPECT_EQ(b[17], 0x00u);
    EXPECT_EQ(b[18], 0x00u);
    EXPECT_EQ(b[19], 0x00u);
    // EntriesLen = 16.
    EXPECT_EQ(b[20], 0x00u);
    EXPECT_EQ(b[21], 0x00u);
    EXPECT_EQ(b[22], 0x00u);
    EXPECT_EQ(b[23], 0x10u);
}

TEST(BuildSubscribeEventgroup, Type2EntryLayout) {
    const auto b = buildSubscribeEventgroup(makeRef());
    ASSERT_GE(b.size(), 40u);
    // Entry at offset 24..39.
    EXPECT_EQ(b[24], 0x06u);  // Type = SubscribeEventgroup
    EXPECT_EQ(b[25], 0x00u);  // IndexFirstOptionRun
    EXPECT_EQ(b[26], 0x00u);  // IndexSecondOptionRun
    EXPECT_EQ(b[27], 0x10u);  // #Opt1=1 | #Opt2=0
    // Service ID = 0xF4E7.
    EXPECT_EQ(b[28], 0xF4u);
    EXPECT_EQ(b[29], 0xE7u);
    // Instance ID = 0x0001.
    EXPECT_EQ(b[30], 0x00u);
    EXPECT_EQ(b[31], 0x01u);
    // Major Version = 0x01.
    EXPECT_EQ(b[32], 0x01u);
    // TTL = 0x000003 (24-bit BE).
    EXPECT_EQ(b[33], 0x00u);
    EXPECT_EQ(b[34], 0x00u);
    EXPECT_EQ(b[35], 0x03u);
    // Reserved(12) | Counter(4) — counter=0 → bytes 12..13 both 0.
    EXPECT_EQ(b[36], 0x00u);
    EXPECT_EQ(b[37], 0x00u);
    // Eventgroup ID = 0x0042.
    EXPECT_EQ(b[38], 0x00u);
    EXPECT_EQ(b[39], 0x42u);
}

TEST(BuildSubscribeEventgroup, OptionsArray) {
    const auto b = buildSubscribeEventgroup(makeRef());
    ASSERT_GE(b.size(), 56u);
    // OptionsLen = 12 at offset 40..43.
    EXPECT_EQ(b[40], 0x00u);
    EXPECT_EQ(b[41], 0x00u);
    EXPECT_EQ(b[42], 0x00u);
    EXPECT_EQ(b[43], 0x0Cu);
    // IPv4 Endpoint option at offset 44..55.
    // Length field = 9 (BE), Type = 0x04, Reserved = 0.
    EXPECT_EQ(b[44], 0x00u);
    EXPECT_EQ(b[45], 0x09u);
    EXPECT_EQ(b[46], 0x04u);
    EXPECT_EQ(b[47], 0x00u);
    // IPv4 address — ipv4_be = 0x030010AC, streamed LSB-first to produce
    // 172.16.0.3 on the wire (byte-order semantics documented at the
    // option-emit site in someip_sd_builder.cpp).
    EXPECT_EQ(b[48], 0xACu);
    EXPECT_EQ(b[49], 0x10u);
    EXPECT_EQ(b[50], 0x00u);
    EXPECT_EQ(b[51], 0x03u);
    // Reserved = 0, L4 = 0x11 (UDP).
    EXPECT_EQ(b[52], 0x00u);
    EXPECT_EQ(b[53], 0x11u);
    // Port = 0x8765 (BE).
    EXPECT_EQ(b[54], 0x87u);
    EXPECT_EQ(b[55], 0x65u);
}

TEST(BuildSubscribeEventgroup, CounterLandsInLowNibbleOfByte13) {
    SubscribeEventgroupParams p = makeRef();
    p.target.counter = 0x5;
    const auto b = buildSubscribeEventgroup(p);
    ASSERT_GE(b.size(), 40u);
    EXPECT_EQ(b[36], 0x00u);
    EXPECT_EQ(b[37], 0x05u);
}

TEST(BuildSubscribeEventgroup, SessionIdIsBigEndian) {
    SubscribeEventgroupParams p = makeRef();
    p.session_id = 0x1234;
    const auto b = buildSubscribeEventgroup(p);
    ASSERT_GE(b.size(), 12u);
    EXPECT_EQ(b[10], 0x12u);
    EXPECT_EQ(b[11], 0x34u);
}

}  // namespace
}  // namespace tc8::stimulus
