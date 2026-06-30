#include "packet_pipeline.h"

#include <algorithm>
#include <cstring>

#include <tins/arp.h>
#include <tins/dot1q.h>
#include <tins/ethernetII.h>
#include <tins/icmp.h>
#include <tins/ip.h>
#include <tins/rawpdu.h>
#include <tins/tcp.h>
#include <tins/udp.h>

#include "tc8/protocol_frames/arp_frame.h"
#include "tc8/protocol_frames/dhcpv4_frame.h"
#include "tc8/protocol_frames/icmpv4_frame.h"
#include "tc8/protocol_frames/ipv4_frame.h"
#include "tc8/protocol_frames/tcp_frame.h"
#include "tc8/protocol_frames/udp_frame.h"

#include "sce_integration/dhcpv4_wire.h"
#include "wire/ip_checksum.h"  // tc8::wire::tcpChecksumValid (RFC 793 pseudo-header SSOT)

namespace tc8::dissect {

using namespace Tins;

namespace {

// Extract the IEEE 802.1Q tag from a captured Ethernet frame, if any.
// Single decode site for the VLAN wire contract — every frame variant
// the pipeline emits copies the result, so the tag is read exactly once
// per frame and the meaning of each TCI field lives in one place.
// `EthernetII::find_pdu<Dot1Q>()` returns null on untagged frames, which
// leaves the default (`present == false`) tag. libtins recognises only
// TPID 0x8100 as `Dot1Q`, so a present tag is always a C-TAG; QinQ
// (0x88a8 S-TAG) is out of scope for this single-tag surface.
::tc8::Dot1QTag dot1qTagFrom(const EthernetII &eth) {
    ::tc8::Dot1QTag tag{};
    if (const Dot1Q *q = eth.find_pdu<Dot1Q>()) {
        tag.present = true;
        tag.tpid = ::tc8::kDot1QTpid;
        tag.pcp  = static_cast<std::uint8_t>(static_cast<unsigned>(q->priority()));
        tag.dei  = static_cast<unsigned>(q->cfi()) != 0U;
        tag.vid  = static_cast<std::uint16_t>(static_cast<unsigned>(q->id()));
    }
    return tag;
}

}  // namespace

PacketPipeline::PacketPipeline(Listener listener) : listener_(std::move(listener)) {
    follower_.new_stream_callback([this](TCPIP::Stream &s) { onNewStream(s); });
}

void PacketPipeline::onNewStream(TCPIP::Stream &s) {
    s.client_data_callback([this](TCPIP::Stream &st) { onClientData(st); });
    s.server_data_callback([this](TCPIP::Stream &st) { onServerData(st); });
}

void PacketPipeline::onClientData(TCPIP::Stream &s) {
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
    dispatcher_.feed(t, payload.data(), payload.size(), listener_);
    payload.clear();
}

void PacketPipeline::onServerData(TCPIP::Stream &s) {
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
    dispatcher_.feed(t, payload.data(), payload.size(), listener_);
    payload.clear();
}

void PacketPipeline::processFrame(const pcap_pkthdr &hdr, const std::uint8_t *bytes, int datalink_type) {
    if (datalink_type != DLT_EN10MB) {
        return;
    }
    // Wall-clock arrival timestamp normalised to microseconds for
    // every Frame variant. Live capture path uses libpcap's default
    // PCAP_TSTAMP_PRECISION_MICRO so `tv_usec` is already in µs;
    // offline replay uses NANO precision and we divide by 1000. The
    // `tstamp_precision_` member is wired by the CLI via
    // `PacketPipeline::setTstampPrecision` once at construction.
    const std::int64_t ts_subsec_us =
        tstamp_precision_ == PCAP_TSTAMP_PRECISION_NANO
            ? static_cast<std::int64_t>(hdr.ts.tv_usec) / 1000LL
            : static_cast<std::int64_t>(hdr.ts.tv_usec);
    const std::int64_t observed_ts_us =
        static_cast<std::int64_t>(hdr.ts.tv_sec) * 1'000'000LL +
        ts_subsec_us;
    try {
        EthernetII eth(bytes, hdr.caplen);

        // IEEE 802.1Q tag (if any), decoded once and copied into every
        // frame variant emitted below. libtins's `find_pdu<>` descends
        // through the Dot1Q layer transparently, so the ARP/IP/ICMP/UDP/
        // TCP lookups already see tagged inner PDUs; this only adds the
        // tag itself as an observable field.
        const ::tc8::Dot1QTag vlan = dot1qTagFrom(eth);

        // ARP §4.2 — no IP layer to descend into. Build the ArpFrame directly
        // from the libtins ARP PDU and hand it to the listener as a variant.
        if (const ARP *arp = eth.find_pdu<ARP>()) {
            ::tc8::ArpFrame af{};
            af.hw_type = arp->hw_addr_format();
            af.proto_type = arp->prot_addr_format();
            af.hw_addr_len = arp->hw_addr_length();
            af.proto_addr_len = arp->prot_addr_length();
            af.opcode = arp->opcode();
            const auto sender_hw = arp->sender_hw_addr();
            const auto target_hw = arp->target_hw_addr();
            std::copy(sender_hw.begin(), sender_hw.end(), af.sender_hw.begin());
            std::copy(target_hw.begin(), target_hw.end(), af.target_hw.begin());
            af.sender_proto_ip = static_cast<std::uint32_t>(arp->sender_ip_addr());
            af.target_proto_ip = static_cast<std::uint32_t>(arp->target_ip_addr());
            const auto eth_src = eth.src_addr();
            const auto eth_dst = eth.dst_addr();
            std::copy(eth_src.begin(), eth_src.end(), af.eth_src.begin());
            std::copy(eth_dst.begin(), eth_dst.end(), af.eth_dst.begin());
            af.observed_ts_us = observed_ts_us;
            af.vlan = vlan;
            listener_(::tc8::CapturedEvent{af});
            return;
        }

        const IP *ip = eth.find_pdu<IP>();
        if (ip == nullptr) {
            return;  // IPv6/etc. — ignore
        }

        // §4.4 IPv4 header — emit one Ipv4Frame event per IPv4 packet so
        // field-level cases (HEADER, CHECKSUM, TTL, VERSION, ADDRESSING)
        // can observe the header independently of whatever inner
        // protocol the frame carries. Falls through to the ICMP/UDP/TCP
        // branches below; listeners that only care about those inner
        // variants ignore the Ipv4Frame alternative via std::get_if.
        // Options region is left nullptr — libtins parses options into a
        // vector of IP::option, not a raw byte range. §4.4 has no OPTIONS
        // subsection in TC8 v3.0 (IPv4_OPTIONS_01..14 deleted V2→V3); if
        // an ICMPv4 consumer carrying IP options in the stimulus (e.g.
        // ICMPv4_TYPE_05 / ERROR_02/03/04) ever needs byte-level
        // observation, serialise on demand rather than point at
        // `ip->options()` internals.
        {
            ::tc8::Ipv4Frame ipf{};
            ipf.version         = static_cast<std::uint8_t>(ip->version());
            ipf.ihl             = static_cast<std::uint8_t>(ip->head_len());
            ipf.tos             = static_cast<std::uint8_t>(ip->tos());
            ipf.total_length    = ip->tot_len();
            ipf.identification  = ip->id();
            ipf.flags           = static_cast<std::uint8_t>(ip->flags());
            ipf.fragment_offset = ip->fragment_offset();
            ipf.ttl             = ip->ttl();
            ipf.protocol        = ip->protocol();
            ipf.header_checksum = ip->checksum();
            ipf.src_addr        = static_cast<std::uint32_t>(ip->src_addr());
            ipf.dst_addr        = static_cast<std::uint32_t>(ip->dst_addr());
            ipf.observed_ts_us  = observed_ts_us;
            ipf.vlan            = vlan;
            listener_(::tc8::CapturedEvent{ipf});
        }

        // ICMPv4 §4.3 — emit one Icmpv4Frame event per frame so Echo /
        // Timestamp cases can observe Type/Code/Id/Seq directly. Branch
        // sits before UDP so the kernel's ICMP traffic never falls
        // through to the SOME/IP port-range dispatcher. Tins's ICMP
        // PDU already exposes `id()` / `sequence()` decoded from the
        // rest-of-header; we pack them back into a 32-bit value so the
        // frame struct matches the RFC 792 wire layout.
        if (const ICMP *icmp = eth.find_pdu<ICMP>()) {
            ::tc8::Icmpv4Frame icf{};
            icf.src_ip   = static_cast<std::uint32_t>(ip->src_addr());
            icf.dst_ip   = static_cast<std::uint32_t>(ip->dst_addr());
            icf.type     = static_cast<std::uint8_t>(icmp->type());
            icf.code     = icmp->code();
            icf.checksum = icmp->checksum();
            icf.rest_of_header =
                (static_cast<std::uint32_t>(icmp->id()) << 16) |
                 static_cast<std::uint32_t>(icmp->sequence());
            if (const RawPDU *raw = icmp->find_pdu<RawPDU>()) {
                const auto &body = raw->payload();
                icf.payload_data = body.data();
                icf.payload_len  = static_cast<std::uint32_t>(body.size());
            }
            // RFC 792 p17 ICMP Timestamp / Timestamp Reply (type=13/14)
            // — libtins parses the three 32-bit timestamp slots into
            // first-class accessors (orig_timestamp_or_address_mask_,
            // recv_timestamp_, trans_timestamp_) rather than into a
            // RawPDU child, so the timestamp slots are reachable only
            // via the typed getters here. Other types reuse those bytes
            // for unrelated semantics (Address Mask, etc.); narrow the
            // copy to the two timestamp-bearing types so non-timestamp
            // captures land at default 0 instead of carrying a
            // misinterpreted slot value.
            //
            // Endian fixup: libtins's `ICMP(buffer, total_sz)` parser
            // calls `original_timestamp(stream.read<uint32_t>())` which
            // performs a native-order memcpy of the 4 wire bytes
            // (i.e., LE interpretation on x86) and then the setter
            // applies `host_to_be` before storing. The corresponding
            // getter returns `be_to_host(stored)` which on LE yields
            // the wire bytes interpreted as little-endian — NOT the
            // RFC 792 "ms since midnight UT" semantic uint32 (which is
            // the big-endian decoding of the wire bytes). Applying
            // `Endian::be_to_host` once more here reverses libtins's
            // half-conversion so the captured field carries the
            // semantic uint32 in host order, matching the literal the
            // tester injected via `kIcmpTimestampOriginate`. On big-
            // endian hosts both `be_to_host` calls are no-ops and the
            // value passes through unchanged.
            if (icmp->type() == ICMP::TIMESTAMP_REQUEST ||
                icmp->type() == ICMP::TIMESTAMP_REPLY) {
                icf.originate_timestamp =
                    Tins::Endian::be_to_host(icmp->original_timestamp());
                icf.receive_timestamp   =
                    Tins::Endian::be_to_host(icmp->receive_timestamp());
                icf.transmit_timestamp  =
                    Tins::Endian::be_to_host(icmp->transmit_timestamp());
            }
            icf.observed_ts_us = observed_ts_us;
            icf.vlan = vlan;
            listener_(::tc8::CapturedEvent{icf});
            return;
        }

        if (const UDP *udp = eth.find_pdu<UDP>()) {
            // RFC 768 wire-legal UDP can carry zero payload (Length=8 =
            // header only). libtins does not attach a `RawPDU` child in
            // that case, so the per-payload pointer/length pair must
            // tolerate a null body — the §4.6.5.4 UDP_FIELDS_07 spec
            // ("Total Length, no data") observes a DUT-emitted 8 B UDP,
            // which would never reach the SCXML if we returned early.
            // Downstream Dhcpv4/SomeIp dispatch already skips on length
            // gates; keeping `body_data` nullable lets every consumer
            // see the encapsulating UDP shape regardless of payload
            // presence.
            const RawPDU *raw = udp->find_pdu<RawPDU>();
            const std::uint8_t *body_data = nullptr;
            std::size_t         body_size = 0;
            if (raw != nullptr) {
                const auto &body = raw->payload();
                body_data = body.data();
                body_size = body.size();
            }

            // Emit a UdpFrame event for every UDP datagram so cross-protocol
            // cases (e.g. §4.2 ARP_04/06 watching DUT Nack's Eth destination)
            // can observe the encapsulating layer. The SomeIp dispatcher is
            // invoked afterwards on the same payload — listeners that only
            // care about SomeIp ignore the UdpFrame variant via std::get_if.
            ::tc8::UdpFrame uf{};
            uf.src_ip = static_cast<std::uint32_t>(ip->src_addr());
            uf.dst_ip = static_cast<std::uint32_t>(ip->dst_addr());
            uf.src_port = udp->sport();
            uf.dst_port = udp->dport();
            uf.length = udp->length();
            uf.checksum = udp->checksum();
            uf.ip_flags = static_cast<std::uint8_t>(ip->flags());
            uf.ip_fragment_offset = ip->fragment_offset();
            const auto eth_src = eth.src_addr();
            const auto eth_dst = eth.dst_addr();
            std::copy(eth_src.begin(), eth_src.end(), uf.eth_src.begin());
            std::copy(eth_dst.begin(), eth_dst.end(), uf.eth_dst.begin());
            uf.payload_data = body_data;
            uf.payload_len = static_cast<std::uint32_t>(body_size);
            uf.observed_ts_us = observed_ts_us;
            uf.vlan = vlan;
            listener_(::tc8::CapturedEvent{uf});

            // §4.7 DHCPv4 — emit one Dhcpv4Frame per BOOTP-shaped UDP
            // datagram on the client/server port pair. The pre-flight
            // gate is `(src_port|dst_port) ∈ {67,68}` plus a length and
            // magic-cookie check on the payload; non-DHCP traffic on
            // those ports (rare in practice) is silently skipped so a
            // malformed packet never raises a Dhcpv4 event. RFC 2131
            // fixes the BOOTP fixed-body length at 240 B — anything
            // shorter cannot carry the magic cookie at offset 236.
            const bool dhcp_port =
                (uf.src_port == 67 || uf.src_port == 68 ||
                 uf.dst_port == 67 || uf.dst_port == 68);
            if (dhcp_port && body_data != nullptr &&
                body_size >= ::tc8::dhcpv4_wire::kOptionsOff) {
                const std::uint8_t* bp = body_data;
                ::tc8::Dhcpv4Frame df{};
                df.eth_src = uf.eth_src;
                df.eth_dst = uf.eth_dst;
                df.src_ip = uf.src_ip;
                df.dst_ip = uf.dst_ip;
                df.ip_flags = uf.ip_flags;
                df.ip_fragment_offset = uf.ip_fragment_offset;
                df.vlan = uf.vlan;  // L2 tag inherited from the carrying frame
                df.src_port = uf.src_port;
                df.dst_port = uf.dst_port;
                // BOOTP fixed-header offsets (op..chaddr) + the magic cookie
                // are owned by dhcpv4_wire.def (TD-02 SSOT); the options TLV
                // walk below has no fixed offsets and stays hand-decoded.
                ::tc8::dhcpv4_wire::decodeBootpFixedHeader(bp, df);
                df.magic_cookie_valid = ::tc8::dhcpv4_wire::magicCookieValid(bp);
                if (df.magic_cookie_valid &&
                    body_size > ::tc8::dhcpv4_wire::kOptionsOff) {
                    df.options_data = bp + ::tc8::dhcpv4_wire::kOptionsOff;
                    df.options_len  = static_cast<std::uint32_t>(
                        body_size - ::tc8::dhcpv4_wire::kOptionsOff);
                    // Walk the TLV chain to locate option 53 (Message
                    // Type) and detect the 0xFF END terminator. RFC 2132
                    // RFC 2132 §9.6 fixes len=1 for option 53. Pad option (0)
                    // and END (255) are length-less; every other code
                    // is followed by a 1-byte length. Stop on END or
                    // first malformed length to keep the parser safe
                    // against truncated wire input.
                    std::uint32_t i = 0;
                    bool saw_end = false;
                    while (i < df.options_len) {
                        const std::uint8_t code = df.options_data[i];
                        if (code == 0xFFU) {
                            saw_end = true;
                            break;
                        }
                        if (code == 0x00U) {
                            // Pad — single byte, no length follows.
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

            // The transport dispatcher (SomeIp etc.) is a no-op on a
            // null body; skip the call rather than handing it
            // (nullptr, 0) to keep the contract obvious.
            if (body_data != nullptr) {
                Transport t{};
                t.proto = Transport::Proto::Udp;
                t.src_ip = uf.src_ip;
                t.dst_ip = uf.dst_ip;
                t.src_port = uf.src_port;
                t.dst_port = uf.dst_port;
                t.observed_ts_us = observed_ts_us;
                dispatcher_.deliver(t, body_data, body_size, listener_);
            }
            return;
        }

        // §4.8 TCP — emit one TcpFrame per segment so BASICS cases can
        // observe RFC 793 Control Bits / SEQ / ACK directly. Runs BEFORE
        // the stream follower so segment-level visibility is preserved;
        // the follower still runs afterwards for SOME/IP-over-TCP
        // dispatch that reassembles app-layer payloads. The two paths
        // consume the same bytes but surface distinct views — §4.8.6.1
        // BASICS traits use `std::get_if<TcpFrame>`, SOME/IP dispatches
        // on reassembled `Transport{Tcp, ...}` via the follower
        // callbacks. No double-listener conflict: a case watches one
        // or the other, not both.
        if (const TCP *tcp = eth.find_pdu<TCP>()) {
            ::tc8::TcpFrame tf{};
            tf.src_ip      = static_cast<std::uint32_t>(ip->src_addr());
            tf.dst_ip      = static_cast<std::uint32_t>(ip->dst_addr());
            tf.src_port    = tcp->sport();
            tf.dst_port    = tcp->dport();
            tf.seq_num     = tcp->seq();
            tf.ack_num     = tcp->ack_seq();
            tf.data_offset = static_cast<std::uint8_t>(tcp->data_offset());
            // libtins `flags()` returns small_uint<12> covering CWR/ECE
            // + reserved + URG/ACK/PSH/RST/SYN/FIN. §4.8.6.1 only
            // observes the low 6 bits (classic Control Bits); truncate
            // to the uint8_t field — ECN bits are discarded but no
            // current case reads them. A future ECN test would widen
            // `TcpFrame::flags` and adjust here.
            tf.flags       = static_cast<std::uint8_t>(tcp->flags() & 0xFFU);
            tf.window      = tcp->window();
            tf.checksum    = tcp->checksum();
            tf.urgent_pointer = tcp->urg_ptr();
            // MSS parsed if advertised (SYN segments only by convention).
            // libtins's `TCP::mss()` returns the BE-decoded uint16 or
            // throws `option_not_found` when the segment carries no
            // kind=2 option. Manual `search_option(MSS).length_field()`
            // is unreliable: PDUOption::length_field() returns the
            // option's *data* length (2 B for MSS) not the wire length
            // (4 B with kind+length prefix).
            try {
                tf.mss = tcp->mss();
            } catch (const std::exception &) {
                // Option absent or malformed: leave mss = 0.
            }
            if (const RawPDU *raw = tcp->find_pdu<RawPDU>()) {
                const auto &body = raw->payload();
                tf.payload_data = body.data();
                tf.payload_len  = static_cast<std::uint32_t>(body.size());
            }
            // RFC 793 §3.1 pseudo-header checksum, validated through the shared
            // tc8::wire::tcpChecksumValid SSOT (the same RFC 1071 fold the segment
            // builder uses). Reads bytes directly from the captured frame — Eth
            // (14 B) + IPv4 (variable) + TCP region are contiguous, pcap on veth
            // carries no FCS, and the IPv4 Total Length bounds the TCP region so any
            // L2 trailer padding stays out of the sum. §4.8.6.2 TCP_CHECKSUM_03
            // reads tf.checksum_valid to verify the DUT's sender-side checksum.
            // This is the sole checksum implementation now that the site no
            // longer re-decodes the wire in Python. See docs/tech-debt.md TD-04
            // (resolved by TD-05).
            tf.checksum_valid = false;
            const std::uint16_t ip_total_len = ip->tot_len();
            const std::uint16_t ip_hdr_len   =
                static_cast<std::uint16_t>(ip->head_len() * 4U);
            constexpr std::size_t kEthHdrLen = 14U;
            if (ip_total_len >= ip_hdr_len &&
                static_cast<std::size_t>(kEthHdrLen) + ip_total_len <= hdr.caplen) {
                const std::uint16_t tcp_seg_len =
                    static_cast<std::uint16_t>(ip_total_len - ip_hdr_len);
                const std::uint8_t *ip_hdr  = bytes + kEthHdrLen;
                const std::uint8_t *tcp_seg = ip_hdr + ip_hdr_len;
                // src/dst IP bytes (NBO) live at IP header offsets 12..15 / 16..19;
                // copy them into *_be values whose memory is NBO (the convention
                // tcpChecksumValid reads). The segment carries its checksum field
                // in place, exactly what the verification form expects.
                std::uint32_t src_be = 0;
                std::uint32_t dst_be = 0;
                std::memcpy(&src_be, ip_hdr + 12, 4);
                std::memcpy(&dst_be, ip_hdr + 16, 4);
                tf.checksum_valid =
                    ::tc8::wire::tcpChecksumValid(src_be, dst_be, tcp_seg, tcp_seg_len);
            }
            // Wall-clock arrival timestamp normalised at function
            // top from `hdr.ts`; same value mirrored into every
            // emitted Frame variant for cross-protocol timing.
            tf.observed_ts_us = observed_ts_us;
            tf.vlan = vlan;
            listener_(::tc8::CapturedEvent{tf});

            follower_.process_packet(eth);
            return;
        }
    } catch (const std::exception &) {
        // malformed frame — skip
    }
}

}  // namespace tc8::dissect
