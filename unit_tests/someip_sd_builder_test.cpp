#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "someip/sd_decode.h"
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

TEST(BuildSubscribeEventgroup, EntryReservedOverrideSetsReservedBits) {
    // A case can set the 12-bit entry Reserved field (byte 12 + high nibble of
    // byte 13) to drive an implementation-defined entry flag, keeping the 4-bit
    // counter in the low nibble of byte 13.
    SubscribeEventgroupParams p = makeRef();
    p.target.entry_reserved = 0x801;  // reserved = 1000 0000 0001
    p.target.counter = 0x5;
    const auto b = buildSubscribeEventgroup(p);
    // (0x801 << 4) | 0x5 = 0x8015, big-endian.
    EXPECT_EQ(b[36], 0x80u);  // high 8 reserved bits
    EXPECT_EQ(b[37], 0x15u);  // low 4 reserved bits (0x1) | counter (0x5)
    EXPECT_EQ(b[38], 0x00u);  // eventgroup ID unshifted
    EXPECT_EQ(b[39], 0x42u);
}

TEST(BuildSubscribeEventgroup, SessionIdIsBigEndian) {
    SubscribeEventgroupParams p = makeRef();
    p.session_id = 0x1234;
    const auto b = buildSubscribeEventgroup(p);
    ASSERT_GE(b.size(), 12u);
    EXPECT_EQ(b[10], 0x12u);
    EXPECT_EQ(b[11], 0x34u);
}

// Default (second_endpoint unset) is byte-identical to the pre-existing
// single-option Subscribe: 56 bytes, OptionsLen 12, #Opt1=1. Guards the
// dual-endpoint addition against regressing every single-option subscriber.
TEST(BuildSubscribeEventgroup, NoSecondEndpointStaysSingleOption) {
    const auto b = buildSubscribeEventgroup(makeRef());
    EXPECT_EQ(b.size(), 56u);
    EXPECT_EQ(b[43], 0x0Cu);  // OptionsLen = 12
    EXPECT_EQ(b[27], 0x10u);  // #Opt1=1 | #Opt2=0
}

// A second (TCP) IPv4 Endpoint option is appended canonically (12B via the
// appendIpv4EndpointOption SSOT) right after the UDP option, and the entry's
// first option run references both (#Opt1=2). This is the dual-transport
// Subscribe a mixed-reliability (RT_BOTH) eventgroup requires.
TEST(BuildSubscribeEventgroup, SecondEndpointAppendsCanonicalTcpOption) {
    SubscribeEventgroupParams p = makeRef();
    p.second_endpoint = Ipv4Endpoint{0x030010AC, 0x9A1B, 0x06};  // 172.16.0.3 : 0x9A1B, TCP
    p.num_options_first_override = std::uint8_t{2};
    const auto b = buildSubscribeEventgroup(p);

    // Payload grows by one 12-byte option: 56 + 12 = 68.
    ASSERT_EQ(b.size(), 68u);
    EXPECT_EQ(b[7], 0x3Cu);   // SOME/IP Length = 48 + 12 = 60
    EXPECT_EQ(b[27], 0x20u);  // #Opt1=2 | #Opt2=0
    EXPECT_EQ(b[43], 0x18u);  // OptionsLen = 24
    EXPECT_EQ(b[53], 0x11u);  // option 0 still UDP
    // Option 1 (TCP) canonical at 56..67.
    EXPECT_EQ(b[56], 0x00u);  // Length hi
    EXPECT_EQ(b[57], 0x09u);  // Length = 9
    EXPECT_EQ(b[58], 0x04u);  // Type = IPv4 Endpoint
    EXPECT_EQ(b[59], 0x00u);  // Reserved
    EXPECT_EQ(b[60], 0xACu);  // 172.16.0.3
    EXPECT_EQ(b[61], 0x10u);
    EXPECT_EQ(b[62], 0x00u);
    EXPECT_EQ(b[63], 0x03u);
    EXPECT_EQ(b[64], 0x00u);  // Reserved
    EXPECT_EQ(b[65], 0x06u);  // L4 = TCP
    EXPECT_EQ(b[66], 0x9Au);  // Port hi
    EXPECT_EQ(b[67], 0x1Bu);  // Port lo
}

// The typed helper forces l4proto to TCP on option 1 (even if the caller passes
// a UDP-default endpoint) and sets #Opt1=2, so a case wires the dual-transport
// Subscribe without hand-encoding option bytes or the option-run nibble.
TEST(SetDualEndpointSubscribe, ForcesTcpAndTwoOptionRun) {
    SubscribeEventgroupParams p = makeRef();
    setDualEndpointSubscribe(p, Ipv4Endpoint{0x040010AC, 0x9A1B, 0x11});  // pass UDP default
    ASSERT_TRUE(p.second_endpoint.has_value());
    EXPECT_EQ(p.second_endpoint->l4proto, 0x06u);      // forced to TCP
    EXPECT_EQ(p.second_endpoint->ipv4_be, 0x040010ACu);
    EXPECT_EQ(p.second_endpoint->port, 0x9A1Bu);
    ASSERT_TRUE(p.num_options_first_override.has_value());
    EXPECT_EQ(*p.num_options_first_override, 2u);

    const auto b = buildSubscribeEventgroup(p);
    ASSERT_EQ(b.size(), 68u);
    EXPECT_EQ(b[65], 0x06u);  // wire carries TCP on option 1
}

// The SD header sits right after the 16-byte SOME/IP header, so the Flags
// byte is at offset 16 and the 24-bit Reserved field at offsets 17..19.
TEST(BuildFindService, ReservedDefaultsToZero) {
    FindServiceParams p{};
    const auto b = buildFindService(p);
    ASSERT_GE(b.size(), 20u);
    EXPECT_EQ(b[16], 0xC0u);  // default Flags (Reboot|Unicast)
    EXPECT_EQ(b[17], 0x00u);
    EXPECT_EQ(b[18], 0x00u);
    EXPECT_EQ(b[19], 0x00u);
}

TEST(BuildFindService, ReservedOverrideSetsHeaderReservedBytes) {
    FindServiceParams p{};
    p.sd_reserved = 0xABCDEF;
    const auto b = buildFindService(p);
    ASSERT_GE(b.size(), 20u);
    EXPECT_EQ(b[16], 0xC0u);  // Flags unaffected by the Reserved override
    EXPECT_EQ(b[17], 0xABu);
    EXPECT_EQ(b[18], 0xCDu);
    EXPECT_EQ(b[19], 0xEFu);
}

TEST(BuildFindServiceWithOption, ReservedDefaultsToZero) {
    FindServiceParams p{};
    const Ipv4Endpoint ep{0x030010AC, 0x8765, 0x11};
    const auto b = buildFindServiceWithOption(p, ep);
    ASSERT_EQ(b.size(), 56u);
    EXPECT_EQ(b[17], 0x00u);
    EXPECT_EQ(b[18], 0x00u);
    EXPECT_EQ(b[19], 0x00u);
}

TEST(BuildFindServiceWithOption, ReservedOverrideSetsHeaderReservedBytes) {
    FindServiceParams p{};
    p.sd_reserved = 0x123456;
    const Ipv4Endpoint ep{0x030010AC, 0x8765, 0x11};
    const auto b = buildFindServiceWithOption(p, ep);
    ASSERT_EQ(b.size(), 56u);  // size invariant to the reserved value
    EXPECT_EQ(b[17], 0x12u);
    EXPECT_EQ(b[18], 0x34u);
    EXPECT_EQ(b[19], 0x56u);
    // Adjacent fields must be uncorrupted by the reserved write: Flags (16),
    // Entries-Array length (20..23 = 16), entry type (24 = 0x00 Find), and
    // Options-Array length (40..43 = 12, one IPv4 endpoint option).
    EXPECT_EQ(b[16], 0xC0u);
    EXPECT_EQ(b[20], 0x00u);
    EXPECT_EQ(b[21], 0x00u);
    EXPECT_EQ(b[22], 0x00u);
    EXPECT_EQ(b[23], 0x10u);
    EXPECT_EQ(b[24], 0x00u);
    EXPECT_EQ(b[43], 0x0Cu);
}

TEST(BuildFindServiceWithOption, DefaultsToUnreferencedIpv4EndpointOption) {
    FindServiceParams p{};
    const Ipv4Endpoint ep{0x030010AC, 0x8765, 0x11};
    const auto b = buildFindServiceWithOption(p, ep);  // 2-arg: type 0x04, unreferenced
    ASSERT_EQ(b.size(), 56u);
    EXPECT_EQ(b[27], 0x00u);  // #Opt1=0 | #Opt2=0 — present but unreferenced
    EXPECT_EQ(b[46], 0x04u);  // option type = IPv4 Endpoint
}

TEST(BuildFindServiceWithReferencedSdEndpointOption, SetsOptRunAndType) {
    FindServiceParams p{};
    const Ipv4Endpoint ep{0x030010AC, 0x8765, 0x11};
    const auto b = buildFindServiceWithReferencedSdEndpointOption(p, ep);
    ASSERT_EQ(b.size(), 56u);   // size invariant to type / reference
    EXPECT_EQ(b[25], 0x00u);    // IndexFirstOptionRun = 0 (option at index 0)
    EXPECT_EQ(b[27], 0x10u);    // #Opt1=1 | #Opt2=0 — option referenced
    EXPECT_EQ(b[46], 0x24u);    // option type = IPv4 SD Endpoint
    EXPECT_EQ(b[47], 0x00u);    // Discardable flag = 0
    // Endpoint carried verbatim: NBO address, L4-proto, BE port.
    EXPECT_EQ(b[48], 0xACu);
    EXPECT_EQ(b[49], 0x10u);
    EXPECT_EQ(b[50], 0x00u);
    EXPECT_EQ(b[51], 0x03u);
    EXPECT_EQ(b[53], 0x11u);    // L4-proto = UDP
    EXPECT_EQ(b[54], 0x87u);    // port BE hi
    EXPECT_EQ(b[55], 0x65u);    // port BE lo
}

// --- SubscribeEventgroupAck/Nack (entry type 0x07) — tester SERVER-role ---

// Reference Ack matching the makeRef() Subscribe so an answer echoes the same
// identity the DUT would have subscribed to.
SubscribeEventgroupAckParams makeAckRef() {
    SubscribeEventgroupAckParams p{};
    p.target.service_id = 0xF4E7;
    p.target.instance_id = 0x0001;
    p.target.eventgroup_id = 0x0042;
    p.target.major_version = 0x01;
    p.target.ttl = 3;
    p.target.counter = 0x0;
    p.session_id = 0x0001;
    p.sd_flags = 0xC0;
    return p;
}

TEST(BuildSubscribeEventgroupAck, UnicastAckIs44BytesNoOptions) {
    const auto b = buildSubscribeEventgroupAck(makeAckRef());
    // No multicast endpoint → no options: 16 SOME/IP + 4 SD + 4 EntriesLen
    // + 16 entry + 4 OptionsLen = 44.
    ASSERT_EQ(b.size(), 44u);
    // SOME/IP header: SD service/method, Length 36, NOTIFICATION/E_OK.
    EXPECT_EQ(b[0], 0xFFu);
    EXPECT_EQ(b[1], 0xFFu);
    EXPECT_EQ(b[2], 0x81u);
    EXPECT_EQ(b[3], 0x00u);
    EXPECT_EQ(b[7], 36u);    // Length field (8 + 28)
    EXPECT_EQ(b[14], 0x02u);  // message type = NOTIFICATION
    EXPECT_EQ(b[15], 0x00u);  // return code = E_OK
    // SD flags + EntriesLen.
    EXPECT_EQ(b[16], 0xC0u);
    EXPECT_EQ(b[23], 0x10u);  // EntriesLen = 16
    // Entry: type 0x07, no options referenced.
    EXPECT_EQ(b[24], 0x07u);
    EXPECT_EQ(b[27], 0x00u);  // #Opt1=0 | #Opt2=0
    EXPECT_EQ(b[28], 0xF4u);  // Service ID
    EXPECT_EQ(b[29], 0xE7u);
    EXPECT_EQ(b[33], 0x00u);  // TTL = 0x000003 (Ack)
    EXPECT_EQ(b[34], 0x00u);
    EXPECT_EQ(b[35], 0x03u);
    EXPECT_EQ(b[38], 0x00u);  // Eventgroup ID = 0x0042
    EXPECT_EQ(b[39], 0x42u);
    // OptionsLen = 0.
    EXPECT_EQ(b[40], 0x00u);
    EXPECT_EQ(b[41], 0x00u);
    EXPECT_EQ(b[42], 0x00u);
    EXPECT_EQ(b[43], 0x00u);
}

TEST(BuildSubscribeEventgroupAck, NackIsTtlZero) {
    // Same shape as the Ack; the Nack is signalled by TTL == 0 (no separate
    // entry type) — the only delta is the 24-bit TTL field at bytes 33..35.
    SubscribeEventgroupAckParams p = makeAckRef();
    p.target.ttl = 0;
    const auto b = buildSubscribeEventgroupAck(p);
    ASSERT_EQ(b.size(), 44u);
    EXPECT_EQ(b[24], 0x07u);  // still entry type 0x07
    EXPECT_EQ(b[33], 0x00u);
    EXPECT_EQ(b[34], 0x00u);
    EXPECT_EQ(b[35], 0x00u);
}

TEST(BuildSubscribeEventgroupAck, CounterAndEntryReservedShareByte13) {
    SubscribeEventgroupAckParams p = makeAckRef();
    p.target.entry_reserved = 0x801;  // reserved = 1000 0000 0001
    p.target.counter = 0x5;
    const auto b = buildSubscribeEventgroupAck(p);
    // (0x801 << 4) | 0x5 = 0x8015, big-endian at bytes 36..37.
    EXPECT_EQ(b[36], 0x80u);
    EXPECT_EQ(b[37], 0x15u);
    EXPECT_EQ(b[38], 0x00u);  // eventgroup ID unshifted
    EXPECT_EQ(b[39], 0x42u);
}

TEST(BuildSubscribeEventgroupAck, MulticastEndpointAddsReferencedOption) {
    SubscribeEventgroupAckParams p = makeAckRef();
    // 239.0.0.3:0x8765 over UDP as the event multicast group.
    p.target.multicast_endpoint = Ipv4Endpoint{0x030000EF, 0x8765, 0x11};
    const auto b = buildSubscribeEventgroupAck(p);
    // 44 + 12 = 56 bytes, one referenced option.
    ASSERT_EQ(b.size(), 56u);
    EXPECT_EQ(b[7], 48u);     // Length field (8 + 40)
    EXPECT_EQ(b[27], 0x10u);  // #Opt1=1 | #Opt2=0
    EXPECT_EQ(b[43], 0x0Cu);  // OptionsLen = 12
    // IPv4 Multicast option: Length 9 (BE), Type 0x14, Reserved 0.
    EXPECT_EQ(b[44], 0x00u);
    EXPECT_EQ(b[45], 0x09u);
    EXPECT_EQ(b[46], 0x14u);
    EXPECT_EQ(b[47], 0x00u);
    // Group address 239.0.0.3 from ipv4_be = 0x030000EF (wire-order bytes).
    EXPECT_EQ(b[48], 0xEFu);
    EXPECT_EQ(b[49], 0x00u);
    EXPECT_EQ(b[50], 0x00u);
    EXPECT_EQ(b[51], 0x03u);
    EXPECT_EQ(b[52], 0x00u);  // Reserved
    EXPECT_EQ(b[53], 0x11u);  // L4 = UDP
    EXPECT_EQ(b[54], 0x87u);  // Port BE
    EXPECT_EQ(b[55], 0x65u);
}

// Offer SD-flags override + StopOffer (ttl 0) — a server-role case drives a
// specific Reboot flag across an Offer stream, and ttl 0 emits a StopOffer.
TEST(BuildOfferService, SdFlagsDefaultAndOverrideAndStopOffer) {
    OfferServiceTarget t{};
    const auto def = buildOfferService(t);
    ASSERT_GE(def.size(), 17u);
    EXPECT_EQ(def[16], 0xC0u);  // default Reboot=1 Unicast=1
    t.sd_flags = 0x40;          // Reboot=0 Unicast=1
    const auto ovr = buildOfferService(t);
    ASSERT_GE(ovr.size(), 17u);
    EXPECT_EQ(ovr[16], 0x40u);
    // ttl == 0 → StopOfferService: the 24-bit entry TTL (bytes 33..35) is 0.
    OfferServiceTarget stop{};
    stop.ttl = 0;
    const auto s = buildOfferService(stop);
    ASSERT_GE(s.size(), 36u);
    EXPECT_EQ(s[33], 0x00u);
    EXPECT_EQ(s[34], 0x00u);
    EXPECT_EQ(s[35], 0x00u);
}

// Byte-pins for the two builders that route through appendSdHeader but had no
// dedicated coverage before the SSOT migration — proves the shared preamble
// emits the same bytes for the Offer-with-endpoint and multi-entry shapes.
TEST(BuildOfferServiceWithEndpoint, HeaderEntryAndOption) {
    OfferServiceWithEndpointTarget t{};
    t.service.service_id = 0xF4E8;
    t.service.session_id = 0x0001;
    t.endpoint.ipv4_be = 0x030010AC;  // 172.16.0.3
    t.endpoint.port = 0x8765;
    t.endpoint.l4proto = 0x11;
    const auto b = buildOfferServiceWithEndpoint(t);
    ASSERT_EQ(b.size(), 56u);
    // SD header preamble via appendSdHeader.
    EXPECT_EQ(b[0], 0xFFu);
    EXPECT_EQ(b[1], 0xFFu);
    EXPECT_EQ(b[2], 0x81u);
    EXPECT_EQ(b[3], 0x00u);
    EXPECT_EQ(b[7], 48u);     // Length
    EXPECT_EQ(b[14], 0x02u);  // NOTIFICATION
    EXPECT_EQ(b[16], 0xC0u);  // flags
    EXPECT_EQ(b[23], 0x10u);  // EntriesLen
    EXPECT_EQ(b[24], 0x01u);  // entry type Offer
    EXPECT_EQ(b[27], 0x10u);  // #Opt1=1
    EXPECT_EQ(b[43], 0x0Cu);  // OptionsLen
    EXPECT_EQ(b[46], 0x04u);  // IPv4 Endpoint option type
}

// A redirect Offer carries BOTH a Type-0x24 SD Endpoint option at options[0] (the
// redirect target) and a Type-0x04 IPv4 Endpoint option at options[1] (the service
// data endpoint), with the entry referencing the 0x04 at IndexFirstOptionRun = 1.
TEST(BuildOfferServiceWithEndpointAndSdEndpointOption, TwoOptionsRedirect) {
    OfferServiceWithEndpointTarget data{};
    data.service.service_id = 0xF4E7;
    data.service.instance_id = 0x0001;
    data.service.session_id = 0x0001;
    data.endpoint.ipv4_be = 0x020010AC;  // 172.16.0.2 (service data endpoint)
    data.endpoint.port = 0x7777;
    data.endpoint.l4proto = 0x11;
    const Ipv4Endpoint sd_ep{0x030010AC, 0x8765, 0x11};  // 172.16.0.3 (SD redirect)
    const auto b = buildOfferServiceWithEndpointAndSdEndpointOption(data, sd_ep);
    ASSERT_EQ(b.size(), 68u);
    EXPECT_EQ(b[7], 60u);       // SOME/IP Length = 60
    EXPECT_EQ(b[24], 0x01u);    // entry type = OfferService
    EXPECT_EQ(b[25], 0x01u);    // IndexFirstOptionRun = 1 (entry references options[1])
    EXPECT_EQ(b[26], 0x00u);    // IndexSecondOptionRun = 0
    EXPECT_EQ(b[27], 0x10u);    // #Opt1=1 | #Opt2=0
    EXPECT_EQ(b[43], 0x18u);    // OptionsLen = 24 (two 12-byte options)
    // options[0] = Type-0x24 SD Endpoint (redirect target 172.16.0.3 : 0x8765).
    EXPECT_EQ(b[46], 0x24u);
    EXPECT_EQ(b[48], 0xACu); EXPECT_EQ(b[49], 0x10u);
    EXPECT_EQ(b[50], 0x00u); EXPECT_EQ(b[51], 0x03u);
    EXPECT_EQ(b[54], 0x87u); EXPECT_EQ(b[55], 0x65u);  // sd_ep port BE
    // options[1] = Type-0x04 IPv4 Endpoint (data endpoint 172.16.0.2 : 0x7777).
    EXPECT_EQ(b[58], 0x04u);
    EXPECT_EQ(b[60], 0xACu); EXPECT_EQ(b[61], 0x10u);
    EXPECT_EQ(b[62], 0x00u); EXPECT_EQ(b[63], 0x02u);
    EXPECT_EQ(b[66], 0x77u); EXPECT_EQ(b[67], 0x77u);  // data_ep port BE
}

// An Offer that delivers a Configuration option carries options[0] = Type-0x04 IPv4
// Endpoint (data endpoint) and options[1] = Type-0x01 Configuration option, with the
// entry referencing BOTH (IndexFirstOptionRun=0, #Opt1=2). Each config item is
// length-prefixed with a single byte counting `key '=' value`, and the sequence ends
// in a zero-length terminator byte. Key/value strings are neutral placeholders — the
// wire encoding is value-agnostic.
TEST(BuildOfferServiceWithEndpointAndConfigOption, EndpointPlusReferencedConfig) {
    OfferServiceWithEndpointTarget data{};
    data.service.service_id = 0xF4E7;
    data.service.instance_id = 0x0001;
    data.service.session_id = 0x0001;
    data.endpoint.ipv4_be = 0x020010AC;  // 172.16.0.2 (service data endpoint)
    data.endpoint.port = 0x7777;
    data.endpoint.l4proto = 0x11;
    const std::vector<std::pair<std::string, std::string>> items{{"foo", "bar"}, {"x", "yz"}};
    const auto b = buildOfferServiceWithEndpointAndConfigOption(data, items);

    // 74 B = 16 (SOME/IP) + 4 (flags) + 4 (EntriesLen) + 16 (entry) + 4 (OptionsLen)
    //      + 12 (endpoint option) + 18 (config option: 4 header + 14 config string).
    ASSERT_EQ(b.size(), 74u);
    EXPECT_EQ(b[7], 0x42u);   // SOME/IP Length = 66 = 20 + 16 (entries) + 30 (options)
    EXPECT_EQ(b[24], 0x01u);  // entry type = OfferService
    EXPECT_EQ(b[25], 0x00u);  // IndexFirstOptionRun = 0
    EXPECT_EQ(b[26], 0x00u);  // IndexSecondOptionRun = 0
    EXPECT_EQ(b[27], 0x20u);  // #Opt1=2 | #Opt2=0 (references both options)
    EXPECT_EQ(b[28], 0xF4u); EXPECT_EQ(b[29], 0xE7u);  // service id
    EXPECT_EQ(b[30], 0x00u); EXPECT_EQ(b[31], 0x01u);  // instance id
    EXPECT_EQ(b[43], 0x1Eu);  // OptionsLen = 30 (12 + 18)

    // options[0] = Type-0x04 IPv4 Endpoint (172.16.0.2 : 0x7777, UDP).
    EXPECT_EQ(b[45], 0x09u);  // option Length
    EXPECT_EQ(b[46], 0x04u);  // type
    EXPECT_EQ(b[48], 0xACu); EXPECT_EQ(b[49], 0x10u);
    EXPECT_EQ(b[50], 0x00u); EXPECT_EQ(b[51], 0x02u);
    EXPECT_EQ(b[53], 0x11u);  // l4proto UDP
    EXPECT_EQ(b[54], 0x77u); EXPECT_EQ(b[55], 0x77u);  // port BE

    // options[1] = Type-0x01 Configuration option, Length = 15 (1 Reserved + 14 cs).
    EXPECT_EQ(b[57], 0x0Fu);  // option Length = 15
    EXPECT_EQ(b[58], 0x01u);  // type = Configuration
    EXPECT_EQ(b[59], 0x00u);  // Reserved
    // Config string: [0x07]"foo=bar" [0x04]"x=yz" [0x00].
    EXPECT_EQ(b[60], 0x07u);  // item len = 1 + 3 (foo) + 3 (bar)
    EXPECT_EQ(b[61], 0x66u);  // 'f'
    EXPECT_EQ(b[64], 0x3Du);  // '=' inside "foo=bar"
    EXPECT_EQ(b[67], 0x72u);  // 'r' (last of "bar")
    EXPECT_EQ(b[68], 0x04u);  // item len = 1 + 1 (x) + 2 (yz)
    EXPECT_EQ(b[69], 0x78u);  // 'x'
    EXPECT_EQ(b[70], 0x3Du);  // '=' inside "x=yz"
    EXPECT_EQ(b[72], 0x7Au);  // 'z' (last of "yz")
    EXPECT_EQ(b[73], 0x00u);  // zero-length terminator
}

// The builder's Configuration option round-trips through the harness's own SD decoder
// (sd_decode.h) — the drift guard between the WRITER (encodeSdConfigOptionBody) and the
// READER, which hand-code the same [len]key=value...[0x00] shape in separate files.
TEST(BuildOfferServiceWithEndpointAndConfigOption, ConfigOptionRoundTripsThroughDecoder) {
    OfferServiceWithEndpointTarget data{};
    data.service.service_id = 0xF4E7;
    data.service.session_id = 0x0001;
    data.endpoint.ipv4_be = 0x020010AC;
    data.endpoint.port = 0x7777;
    data.endpoint.l4proto = 0x11;
    const std::vector<std::pair<std::string, std::string>> items{{"foo", "bar"}, {"x", "yz"}};
    const auto b = buildOfferServiceWithEndpointAndConfigOption(data, items);

    // parseSdInto consumes the SD payload (the datagram past the 16-byte SOME/IP header).
    ::tc8::SdDecoded decoded{};
    ::tc8::parseSdInto(decoded, b.data() + 16, b.size() - 16);
    EXPECT_EQ(decoded.sd_config_item_count, 2u);
    EXPECT_TRUE(decoded.sd_config_has_key("foo"));
    EXPECT_EQ(decoded.sd_config_value_of("foo"), "bar");
    EXPECT_TRUE(decoded.sd_config_has_key("x"));
    EXPECT_EQ(decoded.sd_config_value_of("x"), "yz");
}

TEST(BuildMultiSubscribeEventgroup, HeaderAndTwoEntries) {
    MultiSubscribeEventgroupParams p{};
    p.entries = {SubscribeEventgroupTarget{}, SubscribeEventgroupTarget{}};
    p.entries[1].eventgroup_id = 0x0005;
    p.tester_endpoint.ipv4_be = 0x030010AC;
    p.tester_endpoint.port = 0x8765;
    p.tester_endpoint.l4proto = 0x11;
    p.session_id = 0x0001;
    const auto b = buildMultiSubscribeEventgroup(p);
    // 16 header + 4 SD + 4 EntriesLen + 32 (two entries) + 4 OptionsLen + 12 option.
    ASSERT_EQ(b.size(), 72u);
    EXPECT_EQ(b[0], 0xFFu);
    EXPECT_EQ(b[2], 0x81u);
    EXPECT_EQ(b[14], 0x02u);  // NOTIFICATION
    EXPECT_EQ(b[16], 0xC0u);  // flags
    EXPECT_EQ(b[23], 0x20u);  // EntriesLen = 32 (two entries)
    EXPECT_EQ(b[24], 0x06u);  // first entry type Subscribe
    EXPECT_EQ(b[40], 0x06u);  // second entry type Subscribe (16B later)
    EXPECT_EQ(b[27], 0x10u);  // single-option bundle: entry 0 #Opt1=1
}

// A mixed-reliability bundle (second_endpoint set) appends a second (TCP)
// option and makes EVERY entry reference both (#Opt1=2). Guards the ETS_088
// dual-transport multi-Subscribe wire shape.
TEST(BuildMultiSubscribeEventgroup, SecondEndpointMakesEveryEntryReferenceBoth) {
    MultiSubscribeEventgroupParams p{};
    p.entries = {SubscribeEventgroupTarget{}, SubscribeEventgroupTarget{}};
    p.entries[1].eventgroup_id = 0x0005;
    p.tester_endpoint.ipv4_be = 0x030010AC;
    p.tester_endpoint.port = 0x8765;
    p.tester_endpoint.l4proto = 0x11;
    p.second_endpoint = Ipv4Endpoint{0x030010AC, 0x9A1B, 0x06};  // TCP option 1
    p.session_id = 0x0001;
    const auto b = buildMultiSubscribeEventgroup(p);
    // 16 header + 4 SD + 4 EntriesLen + 32 (two entries) + 4 OptionsLen + 24 (two options).
    ASSERT_EQ(b.size(), 84u);
    EXPECT_EQ(b[23], 0x20u);  // EntriesLen = 32 (two entries)
    EXPECT_EQ(b[27], 0x20u);  // entry 0 #Opt1=2 | #Opt2=0
    EXPECT_EQ(b[43], 0x20u);  // entry 1 #Opt1=2 (16B later)
    EXPECT_EQ(b[59], 0x18u);  // OptionsLen = 24
    EXPECT_EQ(b[61], 0x09u);  // option 0 Length
    EXPECT_EQ(b[69], 0x11u);  // option 0 l4proto UDP
    EXPECT_EQ(b[73], 0x09u);  // option 1 Length
    EXPECT_EQ(b[81], 0x06u);  // option 1 l4proto TCP
}

// per_entry_num_options_first lets a mixed entry reference both options (#Opt1=2)
// while an unreliable entry references the UDP option only (#Opt1=1) — the
// reference bundle shape (ETS_088), so unreliable eventgroups stay UDP-bound.
TEST(BuildMultiSubscribeEventgroup, PerEntryNumOptionsFirstMixesReferences) {
    MultiSubscribeEventgroupParams p{};
    p.entries = {SubscribeEventgroupTarget{}, SubscribeEventgroupTarget{}};
    p.entries[1].eventgroup_id = 0x0005;
    p.tester_endpoint.ipv4_be = 0x030010AC;
    p.tester_endpoint.port = 0x8765;
    p.tester_endpoint.l4proto = 0x11;
    p.second_endpoint = Ipv4Endpoint{0x030010AC, 0x9A1B, 0x06};
    p.per_entry_num_options_first = {2, 1};  // entry 0 dual, entry 1 UDP-only
    p.session_id = 0x0001;
    const auto b = buildMultiSubscribeEventgroup(p);
    ASSERT_EQ(b.size(), 84u);  // both options still present (24 B array)
    EXPECT_EQ(b[27], 0x20u);   // entry 0 #Opt1=2 (UDP + TCP)
    EXPECT_EQ(b[43], 0x10u);   // entry 1 #Opt1=1 (UDP only)
}

TEST(BuildSubscribeEventgroupNack, ForcesTtlZeroIgnoringTargetTtl) {
    // The named Nack wrapper overwrites target.ttl to 0 (Nack) while echoing
    // every other field, regardless of the ttl the caller left set.
    SubscribeEventgroupAckParams p = makeAckRef();
    p.target.ttl = 9;  // must be ignored.
    p.target.counter = 0x5;
    const auto b = buildSubscribeEventgroupNack(p);
    ASSERT_EQ(b.size(), 44u);
    EXPECT_EQ(b[24], 0x07u);  // entry type 0x07
    EXPECT_EQ(b[33], 0x00u);  // TTL forced to 0
    EXPECT_EQ(b[34], 0x00u);
    EXPECT_EQ(b[35], 0x00u);
    EXPECT_EQ(b[37], 0x05u);  // counter still echoed
    EXPECT_EQ(b[39], 0x42u);  // eventgroup still echoed
}

TEST(BuildSubscribeEventgroupAck, MulticastOptionTypeOverride) {
    SubscribeEventgroupAckParams p = makeAckRef();
    p.target.multicast_endpoint = Ipv4Endpoint{0x030000EF, 0x8765, 0x11};
    p.target.multicast_option_type = 0x77;  // drive an unknown option type
    const auto b = buildSubscribeEventgroupAck(p);
    ASSERT_EQ(b.size(), 56u);
    EXPECT_EQ(b[46], 0x77u);
}

// --- OfferService: SD-header Reserved override (mirror of the FindService path) ---

TEST(BuildOfferService, ReservedDefaultsToZero) {
    OfferServiceTarget t{};
    const auto b = buildOfferService(t);
    ASSERT_GE(b.size(), 20u);
    EXPECT_EQ(b[16], 0xC0u);  // Flags default (Reboot|Unicast)
    EXPECT_EQ(b[17], 0x00u);
    EXPECT_EQ(b[18], 0x00u);
    EXPECT_EQ(b[19], 0x00u);
}

TEST(BuildOfferService, ReservedOverrideSetsHeaderReservedBytes) {
    OfferServiceTarget t{};
    t.sd_reserved = 0xABCDEF;
    const auto b = buildOfferService(t);
    ASSERT_GE(b.size(), 20u);
    EXPECT_EQ(b[16], 0xC0u);  // Flags unaffected by the Reserved override
    EXPECT_EQ(b[17], 0xABu);
    EXPECT_EQ(b[18], 0xCDu);
    EXPECT_EQ(b[19], 0xEFu);
    EXPECT_EQ(b[23], 0x10u);  // EntriesLen still 16 (adjacent field uncorrupted)
    EXPECT_EQ(b[24], 0x01u);  // entry type still Offer
}

TEST(BuildOfferServiceWithEndpoint, ReservedOverrideSetsHeaderReservedBytes) {
    OfferServiceWithEndpointTarget t{};
    t.service.sd_reserved = 0x123456;
    t.endpoint.ipv4_be = 0x030010AC;
    t.endpoint.port = 0x8765;
    const auto b = buildOfferServiceWithEndpoint(t);
    ASSERT_EQ(b.size(), 56u);  // size invariant to the reserved value
    EXPECT_EQ(b[17], 0x12u);
    EXPECT_EQ(b[18], 0x34u);
    EXPECT_EQ(b[19], 0x56u);
    EXPECT_EQ(b[27], 0x10u);  // #Opt1=1 (still single referenced option)
    EXPECT_EQ(b[43], 0x0Cu);  // OptionsLen = 12
}

// --- sdIpv4OptionBody SSOT: the body the endpoint-option encoder emits ---

// The public body helper produces exactly the 8 bytes appendIpv4EndpointOption
// streams after its Length/Type/Reserved prefix — the bytes at offsets 48..55 of a
// single-endpoint Offer. Guards that a case building an extra endpoint option via
// sdIpv4OptionBody stays byte-for-byte identical to the mandatory endpoint encoder.
TEST(SdIpv4OptionBody, MatchesAppendedEndpointOptionBody) {
    const Ipv4Endpoint ep{0x030010AC, 0x8765, 0x11};  // 172.16.0.3 : 0x8765, UDP
    const auto body = sdIpv4OptionBody(ep);
    ASSERT_EQ(body.size(), 8u);
    const std::vector<std::uint8_t> expected{0xAC, 0x10, 0x00, 0x03,  // address (NBO, LSB-first)
                                             0x00, 0x11,               // Reserved, L4=UDP
                                             0x87, 0x65};              // Port BE
    EXPECT_EQ(body, expected);

    OfferServiceWithEndpointTarget t{};
    t.endpoint = ep;
    const auto offer = buildOfferServiceWithEndpoint(t);
    ASSERT_EQ(offer.size(), 56u);
    // Option body sits at offsets 48..55 (after Length[44,45]+Type[46]+Reserved[47]).
    const std::vector<std::uint8_t> on_wire(offer.begin() + 48, offer.begin() + 56);
    EXPECT_EQ(on_wire, expected);
}

// --- OfferService referenced extra options (inert unless used) ---

TEST(BuildOfferServiceWithEndpoint, EmptyExtraOptionsIsByteIdenticalSingleOption) {
    OfferServiceWithEndpointTarget t{};
    t.service.service_id = 0xF4E8;
    t.endpoint.ipv4_be = 0x030010AC;
    t.endpoint.port = 0x8765;
    const auto b = buildOfferServiceWithEndpoint(t);
    ASSERT_EQ(b.size(), 56u);   // unchanged single-option shape
    EXPECT_EQ(b[7], 0x30u);     // SOME/IP Length = 48
    EXPECT_EQ(b[27], 0x10u);    // #Opt1=1 | #Opt2=0
    EXPECT_EQ(b[43], 0x0Cu);    // OptionsLen = 12
}

// An unknown-type referenced extra option (type 0x40, 4-byte body) extends the run to
// #Opt1=2 and grows OptionsLen / Length; the option Length counts the Reserved byte
// (spec-correct), and the whole message re-parses through the harness SD decoder.
TEST(BuildOfferServiceWithEndpoint, UnknownTypeExtraOptionReferencedAndRoundTrips) {
    OfferServiceWithEndpointTarget t{};
    t.service.service_id = 0xF4E8;
    t.service.instance_id = 0x0001;
    t.endpoint.ipv4_be = 0x030010AC;  // 172.16.0.3
    t.endpoint.port = 0x8765;
    t.extra_options.push_back({/*type=*/0x40, /*body=*/{0xDE, 0xAD, 0xBE, 0xEF}, /*reserved=*/0});
    const auto b = buildOfferServiceWithEndpoint(t);

    // 56 (single-option) + 8 (Len2+Type1+Reserved1+body4) = 64.
    ASSERT_EQ(b.size(), 64u);
    EXPECT_EQ(b[7], 0x38u);   // SOME/IP Length = 56 (20 + 16 entries + 20 options)
    EXPECT_EQ(b[27], 0x20u);  // #Opt1=2 | #Opt2=0
    EXPECT_EQ(b[43], 0x14u);  // OptionsLen = 20 (12 + 8)
    // Extra option at offset 56..63: Length = 1 + 4 = 5, Type 0x40, Reserved 0.
    EXPECT_EQ(b[56], 0x00u);
    EXPECT_EQ(b[57], 0x05u);
    EXPECT_EQ(b[58], 0x40u);
    EXPECT_EQ(b[59], 0x00u);
    EXPECT_EQ(b[60], 0xDEu);
    EXPECT_EQ(b[63], 0xEFu);

    ::tc8::SdDecoded decoded{};
    ::tc8::parseSdInto(decoded, b.data() + 16, b.size() - 16);
    ASSERT_EQ(decoded.sd_entry_count, 1u);
    EXPECT_EQ(decoded.sd_entries[0].type, ::tc8::sd_entry_type::kOfferService);
    EXPECT_EQ(decoded.sd_entries[0].num_opt1, 2u);   // entry references both options
    ASSERT_EQ(decoded.sd_option_count, 2u);
    EXPECT_EQ(decoded.sd_options[0].type, ::tc8::sd_option_type::kIpv4Endpoint);
    EXPECT_EQ(decoded.sd_options[1].type, 0x40u);    // unknown-type option present
    EXPECT_EQ(decoded.sd_options[1].length, 5u);
}

// A referenced DUPLICATE / CONFLICTING IPv4 Endpoint extra option, its body built via
// sdIpv4OptionBody, decodes as a second endpoint option (address / L4 / port intact).
TEST(BuildOfferServiceWithEndpoint, DuplicateEndpointExtraOptionRoundTrips) {
    OfferServiceWithEndpointTarget t{};
    t.service.service_id = 0xF4E8;
    t.endpoint.ipv4_be = 0x030010AC;  // 172.16.0.3 (mandatory data endpoint)
    t.endpoint.port = 0x8765;
    // Conflicting second endpoint: 172.16.0.4 : 0x9999, UDP.
    const Ipv4Endpoint conflict{0x040010AC, 0x9999, 0x11};
    t.extra_options.push_back({sd_option_type::kIpv4Endpoint, sdIpv4OptionBody(conflict), 0});
    const auto b = buildOfferServiceWithEndpoint(t);

    ASSERT_EQ(b.size(), 68u);   // 56 + 12 (a second canonical endpoint option)
    EXPECT_EQ(b[7], 0x3Cu);     // SOME/IP Length = 60
    EXPECT_EQ(b[27], 0x20u);    // #Opt1=2
    EXPECT_EQ(b[43], 0x18u);    // OptionsLen = 24
    EXPECT_EQ(b[57], 0x09u);    // extra option Length = 9 (Reserved + 8 body)
    EXPECT_EQ(b[58], 0x04u);    // Type = IPv4 Endpoint

    ::tc8::SdDecoded decoded{};
    ::tc8::parseSdInto(decoded, b.data() + 16, b.size() - 16);
    ASSERT_EQ(decoded.sd_option_count, 2u);
    EXPECT_EQ(decoded.sd_options[0].ipv4, 0x030010ACu);
    EXPECT_EQ(decoded.sd_options[0].port, 0x8765u);       // decoder stores port host-order
    EXPECT_EQ(decoded.sd_options[1].type, ::tc8::sd_option_type::kIpv4Endpoint);
    EXPECT_EQ(decoded.sd_options[1].ipv4, 0x040010ACu);   // conflicting address preserved
    EXPECT_EQ(decoded.sd_options[1].port, 0x9999u);
    EXPECT_EQ(decoded.sd_options[1].l4_proto, 0x11u);
}

// --- buildMultiOfferService: N Type-1 entries, one shared referenced endpoint ---

TEST(BuildMultiOfferService, TwoEntriesShareOneEndpointOption) {
    MultiOfferServiceParams p{};
    OfferServiceTarget e{};
    e.service_id = 0xF4E8;
    e.major_version = 0x01;
    e.ttl = 3;
    e.instance_id = 0x0002;
    p.entries.push_back(e);   // first (non-answering) instance
    e.instance_id = 0x0001;
    p.entries.push_back(e);   // second (answering) instance
    p.endpoint = Ipv4Endpoint{0x020010AC, 0x7777, 0x11};  // 172.16.0.2 : 0x7777, UDP
    p.session_id = 0x0001;
    const auto b = buildMultiOfferService(p);

    // 16 header + 4 SD + 4 EntriesLen + 32 (two entries) + 4 OptionsLen + 12 option.
    ASSERT_EQ(b.size(), 72u);
    EXPECT_EQ(b[7], 0x40u);   // SOME/IP Length = 64 (20 + 32 + 12)
    EXPECT_EQ(b[16], 0xC0u);  // flags
    EXPECT_EQ(b[23], 0x20u);  // EntriesLen = 32
    EXPECT_EQ(b[24], 0x01u);  // entry 0 type Offer
    EXPECT_EQ(b[27], 0x10u);  // entry 0 #Opt1=1
    EXPECT_EQ(b[40], 0x01u);  // entry 1 type Offer (16B later)
    EXPECT_EQ(b[43], 0x10u);  // entry 1 #Opt1=1
    EXPECT_EQ(b[59], 0x0Cu);  // OptionsLen = 12
    EXPECT_EQ(b[62], 0x04u);  // shared option type = IPv4 Endpoint

    ::tc8::SdDecoded decoded{};
    ::tc8::parseSdInto(decoded, b.data() + 16, b.size() - 16);
    ASSERT_EQ(decoded.sd_entry_count, 2u);
    EXPECT_EQ(decoded.sd_entries[0].type, ::tc8::sd_entry_type::kOfferService);
    EXPECT_EQ(decoded.sd_entries[0].instance_id, 0x0002u);
    EXPECT_EQ(decoded.sd_entries[1].instance_id, 0x0001u);
    ASSERT_EQ(decoded.sd_option_count, 1u);
    EXPECT_EQ(decoded.sd_options[0].type, ::tc8::sd_option_type::kIpv4Endpoint);
    EXPECT_EQ(decoded.sd_options[0].ipv4, 0x020010ACu);
}

TEST(BuildMultiOfferService, ReservedPassthroughAndStopOfferPerEntry) {
    MultiOfferServiceParams p{};
    p.sd_reserved = 0xABCDEF;
    OfferServiceTarget e{};
    e.service_id = 0xF4E8;
    e.ttl = 0;  // ttl == 0 → StopOffer entry
    p.entries.push_back(e);
    p.endpoint = Ipv4Endpoint{0x020010AC, 0x7777, 0x11};
    const auto b = buildMultiOfferService(p);
    ASSERT_GE(b.size(), 40u);
    EXPECT_EQ(b[17], 0xABu);  // SD Reserved passthrough
    EXPECT_EQ(b[18], 0xCDu);
    EXPECT_EQ(b[19], 0xEFu);
    EXPECT_EQ(b[33], 0x00u);  // entry TTL = 0 (StopOffer)
    EXPECT_EQ(b[34], 0x00u);
    EXPECT_EQ(b[35], 0x00u);
}

// --- SD-header Flags bit constants ---

TEST(SdFlagConstants, RebootAndUnicastBits) {
    EXPECT_EQ(::tc8::sd_flags::kReboot, 0x80u);
    EXPECT_EQ(::tc8::sd_flags::kUnicast, 0x40u);
    // The canonical post-boot flags equal the raw 0xC0 the builders default to.
    EXPECT_EQ(::tc8::sd_flags::kReboot | ::tc8::sd_flags::kUnicast, 0xC0u);
}

}  // namespace
}  // namespace tc8::stimulus
