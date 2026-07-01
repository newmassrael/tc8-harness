// Unit tests for the decode-pcap presentation layer (cli/packet_summary.*,
// docs/tech-debt.md TD-08). These pin the per-protocol summary builders and
// makeCandidate in isolation — coverage the end-to-end decode_pcap_golden ctest
// cannot give for frames outside its fixture. In particular they exercise:
//   * the shared UT decoder (TD-06) via utSummary, including a field the golden
//     fixture does not carry (QueryTcpInfo);
//   * the SD uncapped on-wire totals (TD-09) via a frame with more entries than
//     the parse cap;
//   * the sub-240-byte DHCP "truncated" label (TD-09) via makeCandidate.

#include "cli/packet_summary.h"

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/captured_event.h"

namespace {

using tc8::cli::makeCandidate;
using tc8::cli::sdSummary;
using tc8::cli::utSummary;

// ---- UT decoder (TD-06) --------------------------------------------------

TEST(PacketSummary, UtGetReceivedUdpResponseWithTrailer) {
    // 0x81 = GetReceivedUdp | response bit; req_id 7; status ok; received 1;
    // trailer src 192.168.0.99:12345 payload_len 5 (mirrors golden fixture idx 11).
    const std::vector<std::uint8_t> p{0x81, 0x07, 0x00, 0x01,
                                      192, 168, 0, 99,
                                      0x30, 0x39,   // port 12345 BE
                                      0x00, 0x05};  // payload_len 5 BE
    EXPECT_EQ(utSummary(p.data(), static_cast<std::uint32_t>(p.size())),
              "UT resp GetReceivedUdp ok received=1 src=192.168.0.99:12345 len=5");
}

TEST(PacketSummary, UtRequestShowsReqId) {
    const std::vector<std::uint8_t> p{0x01, 0x07};  // request (bit 7 clear)
    EXPECT_EQ(utSummary(p.data(), static_cast<std::uint32_t>(p.size())),
              "UT req GetReceivedUdp (id=7)");
}

TEST(PacketSummary, UtTruncatedBelowHeader) {
    const std::vector<std::uint8_t> p{0x81};
    EXPECT_EQ(utSummary(p.data(), static_cast<std::uint32_t>(p.size())), "UT (truncated)");
}

TEST(PacketSummary, UtQueryTcpInfoDecodesAllFields) {
    // 0x93 = QueryTcpInfo (0x13) | response bit. body: state, rto(4 BE),
    // retransmits, unacked(4 BE). This opcode is not in the golden fixture.
    const std::vector<std::uint8_t> p{0x93, 0x02, 0x00,
                                      0x01,                    // state = 1
                                      0x00, 0x00, 0x27, 0x10,  // rto = 10000 us
                                      0x03,                    // retransmits = 3
                                      0x00, 0x00, 0x00, 0x05}; // unacked = 5
    EXPECT_EQ(utSummary(p.data(), static_cast<std::uint32_t>(p.size())),
              "UT resp QueryTcpInfo ok state=1 rto=10000us retx=3 unacked=5");
}

// ---- SD summary uncapped wire totals (TD-09) -----------------------------

void appendBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}
void appendBe32(std::vector<std::uint8_t> &b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

// 16-byte OfferService entry (type 0x01, ttl 3, minor 0).
std::vector<std::uint8_t> offerEntry(std::uint16_t service_id, std::uint16_t instance_id) {
    std::vector<std::uint8_t> e;
    e.push_back(0x01);  // type = OfferService
    e.push_back(0x00);  // index first options
    e.push_back(0x00);  // index second options
    e.push_back(0x00);  // #opt1 | #opt2
    appendBe16(e, service_id);
    appendBe16(e, instance_id);
    appendBe32(e, (0x01u << 24) | 3u);  // major_version 1 | ttl 3
    appendBe32(e, 0);                   // minor_version
    return e;
}

// 12-byte IPv4 Endpoint Option (type 0x04, UDP).
std::vector<std::uint8_t> ipv4EndpointOption(std::uint32_t wire_ipv4, std::uint16_t port) {
    std::vector<std::uint8_t> o;
    appendBe16(o, 0x0009);  // Length
    o.push_back(0x04);      // Type = IPv4 Endpoint
    o.push_back(0x00);      // Reserved
    appendBe32(o, wire_ipv4);
    o.push_back(0x00);      // Reserved
    o.push_back(0x11);      // L4 = UDP
    appendBe16(o, port);
    return o;
}

std::vector<std::uint8_t> buildSdPayload(const std::vector<std::uint8_t> &entries,
                                         const std::vector<std::uint8_t> &options) {
    std::vector<std::uint8_t> b{0xC0, 0x00, 0x00, 0x00};  // Flags + Reserved
    appendBe32(b, static_cast<std::uint32_t>(entries.size()));
    b.insert(b.end(), entries.begin(), entries.end());
    appendBe32(b, static_cast<std::uint32_t>(options.size()));
    b.insert(b.end(), options.begin(), options.end());
    return b;
}

TEST(PacketSummary, SdSummaryUsesUncappedWireTotals) {
    // 10 entries (> kMaxSdEntries parse cap of 8) so the "+N more" must come
    // from the uncapped on-wire total, not the capped parsed count; two IPv4
    // endpoint options so the endpoint count is likewise a wire total.
    std::vector<std::uint8_t> entries;
    for (int i = 0; i < 10; ++i) {
        const auto e = offerEntry(static_cast<std::uint16_t>(0x1234 + i), 0x0001);
        entries.insert(entries.end(), e.begin(), e.end());
    }
    std::vector<std::uint8_t> options;
    for (const auto &o : {ipv4EndpointOption(0xC0A80001, 30509),
                          ipv4EndpointOption(0xC0A80001, 30510)}) {
        options.insert(options.end(), o.begin(), o.end());
    }
    const auto payload = buildSdPayload(entries, options);

    tc8::SomeIpFrame f;
    f.service_id = 0xFFFF;  // SD magic — gates SD parsing
    f.method_id = 0x8100;
    f.message_type = 0x02;  // NOTIFICATION
    f.return_code = 0x00;   // E_OK
    f.payload_data = payload.data();
    f.payload_len = static_cast<std::uint32_t>(payload.size());

    EXPECT_EQ(sdSummary(f),
              "SD OfferService svc=0x1234 inst=0x0001 ttl=3 | "
              "OfferService svc=0x1235 inst=0x0001 ttl=3 | "
              "OfferService svc=0x1236 inst=0x0001 ttl=3 | "
              "+7 more | ipv4_endpoints=2");
}

TEST(PacketSummary, SdSummaryTruncatedEntriesNotOverReported) {
    // Declared entries-array length claims 3 entries (48 B) but the payload is
    // truncated to a single entry. The wire total must count entries actually
    // PRESENT (1), not the blind declared/16 (3) — otherwise "+2 more" would be
    // fabricated for entries not on the wire (docs/tech-debt.md TD-09 F1).
    std::vector<std::uint8_t> p{0xC0, 0x00, 0x00, 0x00};  // Flags + Reserved
    appendBe32(p, 48);                                    // declared: 3 entries
    const auto e = offerEntry(0x1234, 0x0001);
    p.insert(p.end(), e.begin(), e.end());               // ...but only 1 present

    tc8::SomeIpFrame f;
    f.service_id = 0xFFFF;
    f.method_id = 0x8100;
    f.message_type = 0x02;
    f.return_code = 0x00;
    f.payload_data = p.data();
    f.payload_len = static_cast<std::uint32_t>(p.size());

    EXPECT_EQ(sdSummary(f), "SD OfferService svc=0x1234 inst=0x0001 ttl=3");
}

TEST(PacketSummary, SdSummaryCountsEndpointOptionsBeyondParseCap) {
    // 10 IPv4 endpoint options (> kMaxSdOptions parse cap of 8) so the endpoint
    // count must come from the uncapped walk-past-cap tally, not the capped
    // stored options (docs/tech-debt.md TD-09).
    std::vector<std::uint8_t> entries;
    const auto e = offerEntry(0x1234, 0x0001);
    entries.insert(entries.end(), e.begin(), e.end());
    std::vector<std::uint8_t> options;
    for (int i = 0; i < 10; ++i) {
        const auto o = ipv4EndpointOption(0xC0A80001, static_cast<std::uint16_t>(30500 + i));
        options.insert(options.end(), o.begin(), o.end());
    }
    const auto payload = buildSdPayload(entries, options);

    tc8::SomeIpFrame f;
    f.service_id = 0xFFFF;
    f.method_id = 0x8100;
    f.message_type = 0x02;
    f.return_code = 0x00;
    f.payload_data = payload.data();
    f.payload_len = static_cast<std::uint32_t>(payload.size());

    EXPECT_EQ(sdSummary(f),
              "SD OfferService svc=0x1234 inst=0x0001 ttl=3 | ipv4_endpoints=10");
}

// ---- makeCandidate: sub-240 DHCP truncation (TD-09) ----------------------

TEST(PacketSummary, MakeCandidateSubMinDhcpLabelledTruncated) {
    // A datagram on the DHCP client/server port pair whose BOOTP body is too
    // short (< 240 B) for the pipeline to raise a Dhcpv4Frame — the exporter
    // must label it truncated rather than as plain UDP.
    tc8::UdpFrame u;
    u.src_port = 68;
    u.dst_port = 67;
    u.length = 108;
    u.payload_len = 100;  // < 240 B magic-cookie offset
    u.payload_data = nullptr;

    const tc8::CapturedEvent ev{u};
    const tc8::cli::Candidate c = makeCandidate(ev);
    EXPECT_EQ(c.protocol, "DHCPv4");
    EXPECT_EQ(c.summary, "DHCPv4 (truncated, 100 B)");
}

TEST(PacketSummary, MakeCandidatePlainUdp) {
    tc8::UdpFrame u;
    u.src_port = 5000;
    u.dst_port = 6000;
    u.length = 50;
    u.payload_len = 42;
    u.payload_data = nullptr;

    const tc8::CapturedEvent ev{u};
    const tc8::cli::Candidate c = makeCandidate(ev);
    EXPECT_EQ(c.protocol, "UDP");
    EXPECT_NE(c.summary.find("len=50"), std::string::npos);
}

// ---- basic builder sanity (TD-08 direct unit test of the summaries) ------

TEST(PacketSummary, DhcpSummaryDiscover) {
    tc8::Dhcpv4Frame f;
    f.op = 1;
    f.message_type = 1;  // Discover
    f.xid = 0xdeadbeef;
    f.chaddr = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    EXPECT_EQ(tc8::cli::dhcpSummary(f),
              "DHCPv4 Discover xid=0xdeadbeef chaddr=02:00:00:00:00:02");
}

TEST(PacketSummary, SomeipResponseSummary) {
    tc8::SomeIpFrame f;
    f.service_id = 0x1234;
    f.method_id = 0x0001;
    f.client_id = 0x0001;
    f.session_id = 0x0001;
    f.message_type = 0x80;  // RESPONSE
    f.return_code = 0x00;   // E_OK
    EXPECT_EQ(tc8::cli::someipSummary(f),
              "Response svc=0x1234 mid=0x0001 client=0x0001 session=0x0001 E_OK");
}

}  // namespace
