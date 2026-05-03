#include "someip_dispatcher.h"

namespace tc8::dissect {

std::uint64_t SomeIpDispatcher::flowKey(const Transport &t) {
    const std::uint64_t src = (std::uint64_t(t.src_ip) << 16) | t.src_port;
    const std::uint64_t dst = (std::uint64_t(t.dst_ip) << 16) | t.dst_port;
    const std::uint64_t mix = src ^ (dst * 0x9e3779b97f4a7c15ULL);
    return mix ^ (static_cast<std::uint64_t>(t.proto) << 63);
}

::tc8::SomeIpFrame SomeIpDispatcher::makeFrame(const Transport &t, const SomeIpHeader &h, const std::uint8_t *payload,
                                               std::size_t payload_len) {
    ::tc8::SomeIpFrame f{};
    f.src_ip = t.src_ip;
    f.dst_ip = t.dst_ip;
    f.src_port = t.src_port;
    f.dst_port = t.dst_port;
    f.is_tcp = (t.proto == Transport::Proto::Tcp);
    f.service_id = h.service_id;
    f.method_id = h.method_id;
    f.length = h.length;
    f.client_id = h.client_id;
    f.session_id = h.session_id;
    f.protocol_version = h.protocol_version;
    f.interface_version = h.interface_version;
    f.message_type = static_cast<std::uint8_t>(h.message_type);
    f.return_code = static_cast<std::uint8_t>(h.return_code);
    f.payload_data = payload;
    f.payload_len = static_cast<std::uint32_t>(payload_len);
    f.observed_ts_us = t.observed_ts_us;
    return f;
}

void SomeIpDispatcher::deliver(const Transport &t, const std::uint8_t *data, std::size_t len,
                               const Listener &listener) {
    std::size_t off = 0;
    while (off < len) {
        auto r = parseSomeIpHeader(data + off, len - off);
        if (!r) {
            return;
        }
        const std::uint8_t *payload = data + off + SomeIpHeader::kHeaderSize;
        const std::size_t payload_len = r->total_size - SomeIpHeader::kHeaderSize;
        listener(::tc8::CapturedEvent{makeFrame(t, r->header, payload, payload_len)});
        off += r->total_size;
    }
}

void SomeIpDispatcher::feed(const Transport &t, const std::uint8_t *data, std::size_t len, const Listener &listener) {
    auto &buf = residuals_[flowKey(t)];
    buf.insert(buf.end(), data, data + len);

    std::size_t off = 0;
    while (true) {
        auto r = parseSomeIpHeader(buf.data() + off, buf.size() - off);
        if (!r) {
            break;
        }
        const std::uint8_t *payload = buf.data() + off + SomeIpHeader::kHeaderSize;
        const std::size_t payload_len = r->total_size - SomeIpHeader::kHeaderSize;
        listener(::tc8::CapturedEvent{makeFrame(t, r->header, payload, payload_len)});
        off += r->total_size;
    }
    if (off > 0) {
        buf.erase(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(off));
    }
}

}  // namespace tc8::dissect
