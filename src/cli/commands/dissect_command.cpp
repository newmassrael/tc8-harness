#include "cli/dissect_command.h"

#include <array>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <string>
#include <type_traits>
#include <variant>

#include <pcap/pcap.h>

#include "capture/pcap_source.h"
#include "dissect/packet_pipeline.h"
#include "tc8/captured_event.h"

namespace tc8::cli {
namespace {

std::string hex(const std::uint8_t *p, std::size_t n) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(kDigits[p[i] >> 4]);
        out.push_back(kDigits[p[i] & 0x0F]);
    }
    return out;
}

template <std::size_t N>
std::string hex(const std::array<std::uint8_t, N> &a) {
    return hex(a.data(), a.size());
}

// One line per event: its type, then `name=value` for every field, in declaration order.
class Line {
public:
    explicit Line(std::uint64_t frame, const char *type) {
        text_ = "frame=" + std::to_string(frame) + " " + type;
    }
    Line &u(const char *name, std::uint64_t v) {
        text_ += std::string(" ") + name + "=" + std::to_string(v);
        return *this;
    }
    Line &i(const char *name, std::int64_t v) {
        text_ += std::string(" ") + name + "=" + std::to_string(v);
        return *this;
    }
    Line &b(const char *name, bool v) { return u(name, v ? 1 : 0); }
    Line &bytes(const char *name, const std::uint8_t *p, std::uint32_t n) {
        text_ += std::string(" ") + name + "=" + (p == nullptr ? std::string("null") : hex(p, n));
        return *this;
    }
    template <std::size_t N>
    Line &arr(const char *name, const std::array<std::uint8_t, N> &a) {
        text_ += std::string(" ") + name + "=" + hex(a);
        return *this;
    }
    Line &vlan(const ::tc8::Dot1QTag &t) {
        return b("vlan_present", t.present).u("vlan_tpid", t.tpid).u("vlan_pcp", t.pcp).b("vlan_dei", t.dei)
            .u("vlan_vid", t.vid);
    }
    Line &envelope(const ::tc8::Ipv4Envelope &e) {
        return u("ip_tos", e.ip_tos).u("ip_ttl", e.ip_ttl).u("ip_identification", e.ip_identification)
            .u("ip_flags", e.ip_flags).u("ip_fragment_offset", e.ip_fragment_offset);
    }
    void print() const { std::printf("%s\n", text_.c_str()); }

private:
    std::string text_;
};

void printEvent(std::uint64_t frame, const ::tc8::CapturedEvent &ev) {
    std::visit(
        [frame](const auto &f) {
            using T = std::decay_t<decltype(f)>;
            if constexpr (std::is_same_v<T, ::tc8::ArpFrame>) {
                Line(frame, "arp").u("hw_type", f.hw_type).u("proto_type", f.proto_type)
                    .u("hw_addr_len", f.hw_addr_len).u("proto_addr_len", f.proto_addr_len).u("opcode", f.opcode)
                    .arr("sender_hw", f.sender_hw).u("sender_proto_ip", f.sender_proto_ip)
                    .arr("target_hw", f.target_hw).u("target_proto_ip", f.target_proto_ip)
                    .arr("eth_src", f.eth_src).arr("eth_dst", f.eth_dst).i("ts", f.observed_ts_us).vlan(f.vlan)
                    .print();
            } else if constexpr (std::is_same_v<T, ::tc8::Icmpv4Frame>) {
                Line(frame, "icmpv4").u("src_ip", f.src_ip).u("dst_ip", f.dst_ip).u("type", f.type)
                    .u("code", f.code).u("checksum", f.checksum).u("rest_of_header", f.rest_of_header)
                    .bytes("payload", f.payload_data, f.payload_len).u("originate", f.originate_timestamp)
                    .u("receive", f.receive_timestamp).u("transmit", f.transmit_timestamp)
                    .i("ts", f.observed_ts_us).vlan(f.vlan).print();
            } else if constexpr (std::is_same_v<T, ::tc8::Ipv4Frame>) {
                Line(frame, "ipv4").u("version", f.version).u("ihl", f.ihl).u("tos", f.tos)
                    .u("total_length", f.total_length).u("identification", f.identification).u("flags", f.flags)
                    .u("fragment_offset", f.fragment_offset).u("ttl", f.ttl).u("protocol", f.protocol)
                    .u("header_checksum", f.header_checksum).u("src_addr", f.src_addr).u("dst_addr", f.dst_addr)
                    .bytes("options", f.options_data, f.options_len).i("ts", f.observed_ts_us).vlan(f.vlan)
                    .print();
            } else if constexpr (std::is_same_v<T, ::tc8::UdpFrame>) {
                Line(frame, "udp").envelope(f).u("src_ip", f.src_ip).u("dst_ip", f.dst_ip)
                    .u("src_port", f.src_port).u("dst_port", f.dst_port).u("length", f.length)
                    .u("checksum", f.checksum).arr("eth_src", f.eth_src).arr("eth_dst", f.eth_dst)
                    .bytes("payload", f.payload_data, f.payload_len).i("ts", f.observed_ts_us).vlan(f.vlan)
                    .print();
            } else if constexpr (std::is_same_v<T, ::tc8::Dhcpv4Frame>) {
                Line(frame, "dhcpv4").envelope(f).arr("eth_src", f.eth_src).arr("eth_dst", f.eth_dst)
                    .u("src_ip", f.src_ip).u("dst_ip", f.dst_ip).u("src_port", f.src_port)
                    .u("dst_port", f.dst_port).u("op", f.op).u("htype", f.htype).u("hlen", f.hlen)
                    .u("hops", f.hops).u("xid", f.xid).u("secs", f.secs).u("flags", f.flags)
                    .u("ciaddr", f.ciaddr).u("yiaddr", f.yiaddr).u("siaddr", f.siaddr).u("giaddr", f.giaddr)
                    .arr("chaddr", f.chaddr).b("magic_cookie_valid", f.magic_cookie_valid)
                    .u("message_type", f.message_type)
                    .b("message_type_option_present", f.message_type_option_present)
                    .b("last_option_is_end", f.last_option_is_end)
                    .bytes("options", f.options_data, f.options_len).i("ts", f.observed_ts_us)
                    .vlan(f.vlan).print();
            } else if constexpr (std::is_same_v<T, ::tc8::TcpFrame>) {
                Line(frame, "tcp").envelope(f).u("src_ip", f.src_ip).u("dst_ip", f.dst_ip)
                    .u("src_port", f.src_port).u("dst_port", f.dst_port).u("seq", f.seq_num).u("ack", f.ack_num)
                    .u("data_offset", f.data_offset).u("flags", f.flags).u("window", f.window)
                    .u("checksum", f.checksum).u("urgent_pointer", f.urgent_pointer).u("mss", f.mss)
                    .bytes("options", f.options_data, f.options_len)
                    .bytes("payload", f.payload_data, f.payload_len).b("checksum_valid", f.checksum_valid)
                    .i("ts", f.observed_ts_us).vlan(f.vlan).print();
            } else if constexpr (std::is_same_v<T, ::tc8::SomeIpFrame>) {
                Line(frame, "someip").u("src_ip", f.src_ip).u("dst_ip", f.dst_ip).u("src_port", f.src_port)
                    .u("dst_port", f.dst_port).b("is_tcp", f.is_tcp).u("service_id", f.service_id)
                    .u("method_id", f.method_id).u("length", f.length).u("client_id", f.client_id)
                    .u("session_id", f.session_id).u("protocol_version", f.protocol_version)
                    .u("interface_version", f.interface_version).u("message_type", f.message_type)
                    .u("return_code", f.return_code).bytes("payload", f.payload_data, f.payload_len)
                    .i("ts", f.observed_ts_us).u("datagram_msg_index", f.datagram_msg_index)
                    .u("datagram_msg_count", f.datagram_msg_count).print();
            }
        },
        ev);
}

bool parseMac(const std::string &text, std::array<std::uint8_t, 6> &out) {
    unsigned b[6] = {};
    if (std::sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return false;
    }
    for (std::size_t k = 0; k < 6; ++k) {
        if (b[k] > 0xFF) {
            return false;
        }
        out[k] = static_cast<std::uint8_t>(b[k]);
    }
    return true;
}

}  // namespace

DissectCommand::DissectCommand(CLI::App &app) {
    sub_ = app.add_subcommand(
        "dissect",
        "Replay a saved pcap through the packet pipeline and print every event a case "
        "would receive, one line each with every field, then the dissection accounting");
    sub_->add_option("pcap_file", pcap_file_, "Path to the saved .pcap")
        ->required()
        ->check(CLI::ExistingFile);
    sub_->add_option("--dut-mac", dut_mac_,
                     "The DUT's MAC (aa:bb:cc:dd:ee:ff), so an undissectable frame of the "
                     "tester's own stimulus is told from one of the DUT's");
}

int DissectCommand::run() {
    auto src = capture::PcapSource::openOffline(pcap_file_);
    const int dlt = src->datalink();
    std::uint64_t frame = 0;
    dissect::PacketPipeline pipeline(
        [&frame](const ::tc8::CapturedEvent &ev) { printEvent(frame, ev); });
    pipeline.setTstampPrecision(src->tstampPrecision());
    if (!dut_mac_.empty()) {
        std::array<std::uint8_t, 6> mac{};
        if (!parseMac(dut_mac_, mac)) {
            std::fprintf(stderr, "error: --dut-mac '%s' is not a MAC address\n", dut_mac_.c_str());
            return 2;
        }
        pipeline.setDutMac(mac);
    }
    while (true) {
        const int n = src->dispatch(/*max_frames=*/-1, [&](const pcap_pkthdr &hdr, const u_char *data) {
            pipeline.processFrame(hdr, data, dlt);
            ++frame;
        });
        if (n < 0) {
            if (n == -2) break;
            std::fprintf(stderr, "dispatch error: %s\n", src->lastError());
            return 1;
        }
        if (n == 0 && src->isOffline()) break;
    }
    const ::tc8::DissectionStats &ds = pipeline.dissectionStats();
    std::printf("dissection frames_seen=%" PRIu64 " truncated=%" PRIu64 " undissectable=%" PRIu64
                " undissectable_possibly_dut=%" PRIu64 " consumer_faults=%" PRIu64 "\n",
                ds.frames_seen, ds.frames_truncated, ds.frames_undissectable,
                ds.frames_undissectable_possibly_dut, ds.consumer_faults);
    return 0;
}

}  // namespace tc8::cli
