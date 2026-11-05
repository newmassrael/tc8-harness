#include "dissect/packet_pipeline.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string>

#include <tins/ip.h>
#include <tins/rawpdu.h>
#include <tins/tcp.h>

#include "tc8/protocol_frames/arp_frame.h"
#include "tc8/protocol_frames/dhcpv4_frame.h"
#include "tc8/protocol_frames/icmpv4_frame.h"
#include "tc8/protocol_frames/ipv4_frame.h"
#include "tc8/protocol_frames/tcp_frame.h"
#include "tc8/protocol_frames/udp_frame.h"
#include "tc8/stimulus_marker.h"

#include "sce_integration/dhcpv4_wire.h"
#include "tc8/wire/arp_packet.h"
#include "tc8/wire/ethernet_frame.h"
#include "tc8/wire/icmpv4_message.h"
#include "tc8/wire/ip_checksum.h"  // tc8::wire::tcpChecksumValid (RFC 793 pseudo-header SSOT)
#include "tc8/wire/ipv4_header.h"
#include "tc8/wire/tcp_segment.h"
#include "tc8/wire/udp_datagram.h"

// The frame is read by the harness's own decoders (tc8/wire/, docs/tech-debt.md TD-69):
// Ethernet and one 802.1Q tag, ARP, IPv4 with its options, ICMPv4, UDP and TCP with its
// options. Each reads every input its standard allows and records deviations instead of
// refusing them; a frame is undissectable only where a header cannot be located at all.
// Until 2026-11-05 every layer went through libtins, whose parsers are stricter than the
// RFCs (an IPv4 options area ending in End of Option List and padding was refused), and
// a refused frame vanished: a reply on the wire read as "no reply".
//
// libtins remains for one job, the reassembly of TCP streams that carry SOME/IP
// (Tins::TCPIP::StreamFollower). It is handed a segment BUILT from the fields this file
// decoded, never the captured bytes, so its parsers no longer decide what was observed.

namespace tc8::dissect {

namespace {

constexpr std::uint8_t kIpProtoIcmp = 1;
constexpr std::uint8_t kIpProtoTcp = 6;
constexpr std::uint8_t kIpProtoUdp = 17;

// The carrying IPv4 header's TOS, TTL, Identification, flags and fragment offset, read
// once per packet and copied into every L4 frame the packet yields. The one site that
// moves these fields, so a new L4 frame cannot carry some of them and forget the rest.
::tc8::Ipv4Envelope ipv4EnvelopeFrom(const ::tc8::wire::Ipv4Header &ip) {
    ::tc8::Ipv4Envelope env{};
    env.ip_tos = ip.tos;
    env.ip_ttl = ip.ttl;
    env.ip_identification = ip.identification;
    env.ip_flags = ip.flags;
    env.ip_fragment_offset = ip.fragment_offset;
    return env;
}

// The frame's IEEE 802.1Q tag, if any: the single decode site for the VLAN wire
// contract, copied into every frame variant the pipeline emits. A present tag is always
// a C-TAG (TPID 0x8100); QinQ (0x88a8 S-TAG) is out of scope for this single-tag surface.
::tc8::Dot1QTag dot1qTagFrom(const ::tc8::wire::EthernetFrame &eth) {
    ::tc8::Dot1QTag tag{};
    if (eth.dot1q) {
        tag.present = true;
        tag.tpid = ::tc8::kDot1QTpid;
        tag.pcp = eth.dot1q->pcp;
        tag.dei = eth.dot1q->dei;
        tag.vid = eth.dot1q->vid;
    }
    return tag;
}

// Does this packet belong to the harness's own DUT-control channel?
//
// Identity is the transport port on either end: a control exchange is a request TO the
// DUT's control port and a response FROM it, so one comparison per direction covers both
// halves without needing to know which side the tester is. Both transports are asked
// because the seam's two backends are free to differ (`TestabilityConfig::use_tcp`), and a
// backend that switches transport must not silently reopen the grading hole. A fragment
// carries no transport header to ask.
//
// See `PacketPipeline::setControlPlanePort` for why the answer is taken once per packet
// rather than per emitted event.
bool isControlPlanePacket(const ::tc8::wire::Ipv4Header &ip, const std::uint8_t *l4, std::size_t l4_len,
                          bool fragmented, std::uint16_t port) {
    if (fragmented) {
        return false;
    }
    if (ip.protocol == kIpProtoUdp) {
        if (const auto udp = ::tc8::wire::decodeUdp(l4, l4_len)) {
            return udp->src_port == port || udp->dst_port == port;
        }
    } else if (ip.protocol == kIpProtoTcp) {
        if (const auto tcp = ::tc8::wire::decodeTcp(l4, l4_len)) {
            return tcp->src_port == port || tcp->dst_port == port;
        }
    }
    return false;
}

// How many bytes of the datagram's payload arrived: what its Total Length says, unless
// fewer arrived (the capture holds what the wire carried) or the field is below the
// header (0 under segmentation offload, or a malformed value), when it is what arrived.
std::size_t ipv4PayloadLen(const ::tc8::wire::Ipv4Header &ip, std::size_t arrived) {
    const std::size_t header = ip.headerLen();
    const std::size_t after_header = arrived - header;
    if (ip.total_length < header) {
        return after_header;
    }
    return std::min<std::size_t>(ip.total_length - header, after_header);
}

// What the listener threw, re-raised under a type of its own so `processFrame` can
// tell a failure of the consumer from a failure of a decoder: both used to land in
// one `catch` that counted nothing, and an exception from the case's own state
// machine was read as a malformed frame. The listener is called from more than one
// place (the dispatcher and the TCP stream follower take it too), so the type is
// given at the one place they all share, the listener itself.
class ConsumerFault : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

}  // namespace

PacketPipeline::PacketPipeline(Listener listener)
    : listener_([inner = std::move(listener)](const ::tc8::CapturedEvent &ev) {
          try {
              inner(ev);
          } catch (const std::exception &e) {
              throw ConsumerFault(e.what());
          } catch (...) {
              throw ConsumerFault("the listener threw a non-standard exception");
          }
      }) {
    follower_.new_stream_callback([this](Tins::TCPIP::Stream &s) { onNewStream(s); });
}

void PacketPipeline::noteUndissectable(const pcap_pkthdr &hdr, const std::uint8_t *bytes,
                                       std::uint64_t frame_idx, const char *reason) {
    ++stats_.frames_undissectable;
    // The tester's own malformed stimulus is told apart by the Ethernet source. A run
    // that named no DUT MAC, or a frame too short to carry a source, cannot tell, and
    // counts it as possibly the DUT's.
    constexpr std::size_t kEthSrcOffset = 6;
    const bool dut_mac_named = dut_mac_ != std::array<std::uint8_t, 6>{};
    if (dut_mac_named && hdr.caplen >= kEthSrcOffset + dut_mac_.size() &&
        !std::equal(dut_mac_.begin(), dut_mac_.end(), bytes + kEthSrcOffset)) {
        return;
    }
    ++stats_.frames_undissectable_possibly_dut;
    if (!stats_.first_undissectable_frame) {
        stats_.first_undissectable_frame = frame_idx;
        stats_.first_undissectable_reason = reason;
    }
}

void PacketPipeline::onNewStream(Tins::TCPIP::Stream &s) {
    s.client_data_callback([this](Tins::TCPIP::Stream &st) { onClientData(st); });
    s.server_data_callback([this](Tins::TCPIP::Stream &st) { onServerData(st); });
}

void PacketPipeline::onClientData(Tins::TCPIP::Stream &s) {
    auto &payload = s.client_payload();
    if (payload.empty()) {
        return;
    }
    Transport t{};
    t.proto = Transport::Proto::Tcp;
    t.src_ip = static_cast<std::uint32_t>(s.client_addr_v4());
    t.dst_ip = static_cast<std::uint32_t>(s.server_addr_v4());
    t.src_port = s.client_port();
    t.dst_port = s.server_port();
    t.observed_ts_us = last_packet_ts_us_;  // arrival stamp of the completing segment.
    dispatcher_.feed(t, payload.data(), payload.size(), listener_);
    payload.clear();
}

void PacketPipeline::onServerData(Tins::TCPIP::Stream &s) {
    auto &payload = s.server_payload();
    if (payload.empty()) {
        return;
    }
    Transport t{};
    t.proto = Transport::Proto::Tcp;
    t.src_ip = static_cast<std::uint32_t>(s.server_addr_v4());
    t.dst_ip = static_cast<std::uint32_t>(s.client_addr_v4());
    t.src_port = s.server_port();
    t.dst_port = s.client_port();
    t.observed_ts_us = last_packet_ts_us_;  // arrival stamp of the completing segment.
    dispatcher_.feed(t, payload.data(), payload.size(), listener_);
    payload.clear();
}

void PacketPipeline::processFrame(const pcap_pkthdr &hdr, const std::uint8_t *bytes, int datalink_type) {
    // Counted before anything can return, so a frame's position here is its index in
    // the saved pcap (tc8::DissectionStats::frames_seen).
    const std::uint64_t frame_idx = stats_.frames_seen++;
    if (datalink_type != DLT_EN10MB) {
        return;
    }
    // Refuse a frame the capture cut short. Everything below dissects `caplen`
    // bytes, so a frame longer than the snaplen does not fail — it decodes
    // SHORT and looks plausible. Dropping it keeps a fabricated observation out
    // of the verdict; the count is what tells the run its capture was not the
    // wire (see dissectionStats()).
    if (hdr.caplen < hdr.len) {
        ++stats_.frames_truncated;
        return;
    }
    // Wall-clock arrival timestamp normalised to microseconds for every Frame variant.
    // The live capture path uses libpcap's default PCAP_TSTAMP_PRECISION_MICRO so
    // `tv_usec` is already in µs; offline replay uses NANO precision and we divide by
    // 1000. `tstamp_precision_` is wired by the CLI via setTstampPrecision.
    const std::int64_t ts_subsec_us =
        tstamp_precision_ == PCAP_TSTAMP_PRECISION_NANO
            ? static_cast<std::int64_t>(hdr.ts.tv_usec) / 1000LL
            : static_cast<std::int64_t>(hdr.ts.tv_usec);
    const std::int64_t observed_ts_us =
        static_cast<std::int64_t>(hdr.ts.tv_sec) * 1'000'000LL + ts_subsec_us;
    // Make the arrival stamp reachable from the TCP follower callbacks: onClientData /
    // onServerData fire synchronously inside follower_.process_packet below and read this
    // member to stamp the reassembled Transport (the UDP path sets it inline instead).
    last_packet_ts_us_ = observed_ts_us;
    try {
        dissectFrame(hdr, bytes, frame_idx, observed_ts_us);
    } catch (const ConsumerFault &e) {
        // The frame was read; the case's own code failed on it.
        ++stats_.consumer_faults;
        if (!stats_.first_consumer_fault_frame) {
            stats_.first_consumer_fault_frame = frame_idx;
            stats_.first_consumer_fault_reason = e.what();
        }
    } catch (const std::exception &e) {
        // The SOME/IP dispatcher or the stream follower could not handle what the
        // decoders read. Counted like a frame no decoder could read: an event the case
        // might have needed was not delivered.
        noteUndissectable(hdr, bytes, frame_idx, e.what());
    } catch (...) {
        noteUndissectable(hdr, bytes, frame_idx, "a dissector threw a non-standard exception");
    }
}

void PacketPipeline::dissectFrame(const pcap_pkthdr &hdr, const std::uint8_t *bytes, std::uint64_t frame_idx,
                                  std::int64_t observed_ts_us) {
    const auto eth = ::tc8::wire::decodeEthernet(bytes, hdr.caplen);
    if (!eth) {
        noteUndissectable(hdr, bytes, frame_idx, "an Ethernet frame shorter than its header or tag");
        return;
    }
    const ::tc8::Dot1QTag vlan = dot1qTagFrom(*eth);

    // ARP §4.2 — no IP layer to descend into.
    if (eth->ether_type == ::tc8::wire::kEtherTypeArp) {
        const auto arp = ::tc8::wire::decodeArp(eth->payload, eth->payload_len);
        if (!arp) {
            noteUndissectable(hdr, bytes, frame_idx, "an ARP packet shorter than its address fields");
            return;
        }
        ::tc8::ArpFrame af{};
        af.hw_type = arp->hw_type;
        af.proto_type = arp->proto_type;
        af.hw_addr_len = arp->hw_addr_len;
        af.proto_addr_len = arp->proto_addr_len;
        af.opcode = arp->opcode;
        af.sender_hw = arp->sender_hw;
        af.sender_proto_ip = arp->sender_proto_be;
        af.target_hw = arp->target_hw;
        af.target_proto_ip = arp->target_proto_be;
        af.eth_src = eth->src;
        af.eth_dst = eth->dst;
        af.observed_ts_us = observed_ts_us;
        af.vlan = vlan;
        listener_(::tc8::CapturedEvent{af});
        return;
    }
    if (eth->ether_type != ::tc8::wire::kEtherTypeIpv4) {
        return;  // IPv6 and other types — not observed
    }

    const auto ip = ::tc8::wire::decodeIpv4Header(eth->payload, eth->payload_len);
    if (!ip) {
        noteUndissectable(hdr, bytes, frame_idx, "an IPv4 header that cannot be located");
        return;
    }
    const std::uint8_t *l4 = eth->payload + ip->headerLen();
    const std::size_t l4_len = ipv4PayloadLen(*ip, eth->payload_len);
    // A fragment carries a part of the datagram's payload, so no transport header is read
    // from it: every fragment yields its Ipv4Frame and nothing else, and reassembly is a
    // case's to observe.
    const bool fragmented = (ip->flags & 0x1U) != 0U || ip->fragment_offset != 0U;

    // The harness's own control channel is not traffic under test. Decided once, here,
    // so that EVERY alternative this packet would fan out into (Ipv4Frame, UdpFrame,
    // TcpFrame, ...) is withheld together — see `setControlPlanePort`. After the ARP
    // branch because ARP carries no transport port and so can never be classified by
    // this rule; the comment on the setter states what that leaves uncovered.
    if (control_plane_port_ != 0 && isControlPlanePacket(*ip, l4, l4_len, fragmented, control_plane_port_)) {
        ++control_plane_frames_;
        // Withheld as a frame, but if it acknowledges a stimulus step, the step's name is
        // delivered here — in capture order, which is the only place its position means
        // anything (tc8/stimulus_marker.h).
        if (marker_listener_) {
            if (auto name = ::tc8::StimulusMarkers::take(bytes, hdr.caplen)) {
                marker_listener_(*name);
            }
        }
        return;
    }

    // §4.4 IPv4 header — one Ipv4Frame per IPv4 packet, so field-level cases (HEADER,
    // CHECKSUM, TTL, VERSION, ADDRESSING) observe the header independently of whatever
    // inner protocol the packet carries.
    {
        ::tc8::Ipv4Frame ipf{};
        ipf.version = ip->version;
        ipf.ihl = ip->ihl;
        ipf.tos = ip->tos;
        ipf.total_length = ip->total_length;
        ipf.identification = ip->identification;
        ipf.flags = ip->flags;
        ipf.fragment_offset = ip->fragment_offset;
        ipf.ttl = ip->ttl;
        ipf.protocol = ip->protocol;
        ipf.header_checksum = ip->header_checksum;
        ipf.src_addr = ip->src_be;
        ipf.dst_addr = ip->dst_be;
        ipf.observed_ts_us = observed_ts_us;
        ipf.vlan = vlan;
        listener_(::tc8::CapturedEvent{ipf});
    }
    if (fragmented) {
        return;
    }

    switch (ip->protocol) {
        case kIpProtoIcmp:
            dissectIcmp(hdr, bytes, frame_idx, *ip, l4, l4_len, vlan, observed_ts_us);
            return;
        case kIpProtoUdp:
            dissectUdp(hdr, bytes, frame_idx, *eth, *ip, l4, l4_len, vlan, observed_ts_us);
            return;
        case kIpProtoTcp:
            dissectTcp(hdr, bytes, frame_idx, *ip, l4, l4_len, vlan, observed_ts_us);
            return;
        default:
            return;
    }
}

// ICMPv4 §4.3 — one Icmpv4Frame per message, so Echo / Timestamp cases observe Type, Code,
// the rest of the header and the payload directly.
void PacketPipeline::dissectIcmp(const pcap_pkthdr &hdr, const std::uint8_t *bytes, std::uint64_t frame_idx,
                                 const ::tc8::wire::Ipv4Header &ip, const std::uint8_t *l4,
                                 std::size_t l4_len, const ::tc8::Dot1QTag &vlan,
                                 std::int64_t observed_ts_us) {
    const auto icmp = ::tc8::wire::decodeIcmpv4(l4, l4_len);
    if (!icmp) {
        noteUndissectable(hdr, bytes, frame_idx, "an ICMPv4 message shorter than its type's fixed part");
        return;
    }
    ::tc8::Icmpv4Frame icf{};
    icf.src_ip = ip.src_be;
    icf.dst_ip = ip.dst_be;
    icf.type = icmp->type;
    icf.code = icmp->code;
    icf.checksum = icmp->checksum;
    icf.rest_of_header = icmp->rest_of_header;
    icf.payload_data = icmp->payload;
    icf.payload_len = static_cast<std::uint32_t>(icmp->payload_len);
    // RFC 792 p17 Timestamp / Timestamp Reply: the three 32-bit slots, read big-endian, so
    // each carries the "milliseconds since midnight UT" value the tester injected.
    icf.originate_timestamp = icmp->originate_timestamp;
    icf.receive_timestamp = icmp->receive_timestamp;
    icf.transmit_timestamp = icmp->transmit_timestamp;
    icf.observed_ts_us = observed_ts_us;
    icf.vlan = vlan;
    listener_(::tc8::CapturedEvent{icf});
}

void PacketPipeline::dissectUdp(const pcap_pkthdr &hdr, const std::uint8_t *bytes, std::uint64_t frame_idx,
                                const ::tc8::wire::EthernetFrame &eth, const ::tc8::wire::Ipv4Header &ip,
                                const std::uint8_t *l4, std::size_t l4_len, const ::tc8::Dot1QTag &vlan,
                                std::int64_t observed_ts_us) {
    const auto udp = ::tc8::wire::decodeUdp(l4, l4_len);
    if (!udp) {
        noteUndissectable(hdr, bytes, frame_idx, "a UDP datagram shorter than its header");
        return;
    }
    // A UdpFrame for every datagram, so cross-protocol cases (e.g. §4.2 ARP_04/06 watching
    // a DUT Nack's Ethernet destination) observe the encapsulating layer. RFC 768 allows a
    // datagram with no data (Length 8, which §4.6.5.4 UDP_FIELDS_07 observes), so the payload pointer
    // may be null; consumers that need data gate on its length.
    ::tc8::UdpFrame uf{};
    static_cast<::tc8::Ipv4Envelope &>(uf) = ipv4EnvelopeFrom(ip);
    uf.src_ip = ip.src_be;
    uf.dst_ip = ip.dst_be;
    uf.src_port = udp->src_port;
    uf.dst_port = udp->dst_port;
    uf.length = udp->length;
    uf.checksum = udp->checksum;
    uf.eth_src = eth.src;
    uf.eth_dst = eth.dst;
    uf.payload_data = udp->payload;
    uf.payload_len = static_cast<std::uint32_t>(udp->payload_len);
    uf.observed_ts_us = observed_ts_us;
    uf.vlan = vlan;
    listener_(::tc8::CapturedEvent{uf});

    // §4.7 DHCPv4 — one Dhcpv4Frame per BOOTP-shaped datagram on the client/server port
    // pair: `(src_port|dst_port) ∈ {67,68}` plus a length and magic-cookie check, so
    // non-DHCP traffic on those ports never raises a Dhcpv4 event. RFC 2131 fixes the
    // BOOTP fixed body at 240 B, the magic cookie at offset 236.
    const bool dhcp_port = ::tc8::isDhcpPortPair(uf.src_port, uf.dst_port);
    if (dhcp_port && udp->payload != nullptr && udp->payload_len >= ::tc8::dhcpv4_wire::kOptionsOff) {
        const std::uint8_t *bp = udp->payload;
        ::tc8::Dhcpv4Frame df{};
        df.eth_src = uf.eth_src;
        df.eth_dst = uf.eth_dst;
        df.src_ip = uf.src_ip;
        df.dst_ip = uf.dst_ip;
        static_cast<::tc8::Ipv4Envelope &>(df) = uf;  // the datagram's own IPv4 header
        df.vlan = uf.vlan;  // L2 tag inherited from the carrying frame
        df.src_port = uf.src_port;
        df.dst_port = uf.dst_port;
        // BOOTP fixed-header offsets (op..chaddr) + the magic cookie are owned by
        // dhcpv4_wire.def (TD-02 SSOT); the options TLV walk below has no fixed offsets.
        ::tc8::dhcpv4_wire::decodeBootpFixedHeader(bp, df);
        df.magic_cookie_valid = ::tc8::dhcpv4_wire::magicCookieValid(bp);
        if (df.magic_cookie_valid && udp->payload_len > ::tc8::dhcpv4_wire::kOptionsOff) {
            df.options_data = bp + ::tc8::dhcpv4_wire::kOptionsOff;
            df.options_len = static_cast<std::uint32_t>(udp->payload_len - ::tc8::dhcpv4_wire::kOptionsOff);
            // Walk the TLV chain to locate option 53 (Message Type, RFC 2132 §9.6, len 1)
            // and detect the 0xFF END terminator. Pad (0) and END (255) carry no length;
            // every other code is followed by one length byte. Stop on END or on the
            // first length that runs past the options.
            std::uint32_t i = 0;
            bool saw_end = false;
            while (i < df.options_len) {
                const std::uint8_t code = df.options_data[i];
                if (code == 0xFFU) {
                    saw_end = true;
                    break;
                }
                if (code == 0x00U) {
                    ++i;
                    continue;
                }
                if (i + 1U >= df.options_len) break;
                const std::uint8_t opt_len = df.options_data[i + 1];
                if (i + 2U + opt_len > df.options_len) break;
                if (code == 53U && opt_len == 1U) {
                    df.message_type_option_present = true;
                    df.message_type = df.options_data[i + 2];
                }
                i = i + 2U + opt_len;
            }
            df.last_option_is_end = saw_end;
        }
        df.observed_ts_us = observed_ts_us;
        listener_(::tc8::CapturedEvent{df});
    }

    // The transport dispatcher (SOME/IP etc.) is handed only a datagram with data.
    if (udp->payload != nullptr) {
        Transport t{};
        t.proto = Transport::Proto::Udp;
        t.src_ip = uf.src_ip;
        t.dst_ip = uf.dst_ip;
        t.src_port = uf.src_port;
        t.dst_port = uf.dst_port;
        t.observed_ts_us = observed_ts_us;
        dispatcher_.deliver(t, udp->payload, udp->payload_len, listener_);
    }
}

// §4.8 TCP — one TcpFrame per segment so §4.8.6.1 BASICS cases observe RFC 793 Control Bits,
// SEQ and ACK directly, BEFORE the stream follower, which reassembles the SOME/IP over
// TCP payloads it carries. The two consume the same bytes and surface distinct views:
// a case watches one or the other.
void PacketPipeline::dissectTcp(const pcap_pkthdr &hdr, const std::uint8_t *bytes, std::uint64_t frame_idx,
                                const ::tc8::wire::Ipv4Header &ip, const std::uint8_t *l4,
                                std::size_t l4_len, const ::tc8::Dot1QTag &vlan,
                                std::int64_t observed_ts_us) {
    const auto tcp = ::tc8::wire::decodeTcp(l4, l4_len);
    if (!tcp) {
        noteUndissectable(hdr, bytes, frame_idx, "a TCP header that cannot be located");
        return;
    }
    ::tc8::TcpFrame tf{};
    static_cast<::tc8::Ipv4Envelope &>(tf) = ipv4EnvelopeFrom(ip);
    tf.src_ip = ip.src_be;
    tf.dst_ip = ip.dst_be;
    tf.src_port = tcp->src_port;
    tf.dst_port = tcp->dst_port;
    tf.seq_num = tcp->seq;
    tf.ack_num = tcp->ack;
    tf.data_offset = tcp->data_offset;
    // The classic Control Bits plus CWR / ECE; the four bits before them are not carried.
    tf.flags = tcp->flags;
    tf.window = tcp->window;
    tf.checksum = tcp->checksum;
    tf.urgent_pointer = tcp->urgent_pointer;
    // The MSS a well-formed MSS option advertises (SYN segments by convention), else 0.
    tf.mss = tcp->mss.value_or(0);
    tf.payload_data = tcp->payload;
    tf.payload_len = static_cast<std::uint32_t>(tcp->payload_len);
    // RFC 793 §3.1 pseudo-header checksum, validated through the shared
    // tc8::wire::tcpChecksumValid SSOT over the segment as the datagram's Total Length
    // bounds it. §4.8.6.2 TCP_CHECKSUM_03 reads tf.checksum_valid to verify the DUT's sender-side
    // checksum. A datagram whose Total Length is not all there cannot be summed.
    const std::size_t segment_len = ip.total_length >= ip.headerLen()
                                        ? static_cast<std::size_t>(ip.total_length) - ip.headerLen()
                                        : 0U;
    tf.checksum_valid = segment_len >= ::tc8::wire::kTcpFixedHeaderLen && segment_len <= l4_len &&
                        ::tc8::wire::tcpChecksumValid(ip.src_be, ip.dst_be, l4,
                                                      static_cast<std::uint16_t>(segment_len));
    tf.observed_ts_us = observed_ts_us;
    tf.vlan = vlan;
    listener_(::tc8::CapturedEvent{tf});

    followTcp(ip, *tcp);
}

// Hand the segment to the stream follower, BUILT from the decoded fields: the follower
// reassembles, it does not read the wire.
void PacketPipeline::followTcp(const ::tc8::wire::Ipv4Header &ip, const ::tc8::wire::TcpSegment &tcp) {
    Tins::TCP segment(tcp.dst_port, tcp.src_port);
    segment.seq(tcp.seq);
    segment.ack_seq(tcp.ack);
    segment.flags(static_cast<Tins::small_uint<12>>(tcp.flags));
    segment.window(tcp.window);
    if (tcp.payload != nullptr) {
        segment.inner_pdu(Tins::RawPDU(tcp.payload, static_cast<std::uint32_t>(tcp.payload_len)));
    }
    Tins::IP packet(Tins::IPv4Address(ip.dst_be), Tins::IPv4Address(ip.src_be));
    packet.inner_pdu(segment);
    follower_.process_packet(packet);
}

}  // namespace tc8::dissect
