#include "someip_header.h"

#include "someip/wire.h"

namespace tc8::dissect {

// The wire-constant enums now live in the neutral someip/protocol.h leaf;
// pull them into this TU so the parser code reads unqualified. The big-endian
// readers are the shared someip/wire.h SSOT (the inverse of its putBeNN writers),
// not a per-file copy.
using someip::getBe16;
using someip::getBe32;
using someip::MessageType;
using someip::ReturnCode;

std::optional<ParseResult> parseSomeIpHeader(const std::uint8_t *data, std::size_t len) {
    if (len < 8) {
        return std::nullopt;
    }
    const std::uint32_t length_field = getBe32(data + 4);
    // length 는 message_id + length 이후 필드 크기 — 최소 8 (request_id + 4바이트).
    if (length_field < 8) {
        return std::nullopt;
    }
    const std::size_t total = static_cast<std::size_t>(length_field) + 8;
    if (len < total) {
        return std::nullopt;
    }
    // Protocol Version (header byte 12) is a wire invariant: PRS_SOMEIP_00052
    // fixes it at 0x01. Requiring it here rejects a non-SOME/IP UDP payload
    // whose bytes [4..7] happen to satisfy the length arithmetic above —
    // without this gate, such a datagram (e.g. a longer Upper-Tester response
    // or a data-port stimulus) would be mis-decoded as SOME/IP. The dispatcher
    // feeds EVERY UDP payload through here regardless of port, so the version
    // check is what keeps that port-agnostic feed honest.
    if (data[12] != 0x01) {
        return std::nullopt;
    }

    ParseResult r{};
    r.header.service_id = getBe16(data + 0);
    r.header.method_id = getBe16(data + 2);
    r.header.length = length_field;
    r.header.client_id = getBe16(data + 8);
    r.header.session_id = getBe16(data + 10);
    r.header.protocol_version = data[12];
    r.header.interface_version = data[13];
    r.header.message_type = static_cast<MessageType>(data[14]);
    r.header.return_code = static_cast<ReturnCode>(data[15]);
    r.total_size = total;
    return r;
}

const char *messageTypeName(MessageType t) {
    switch (t) {
    case MessageType::REQUEST:
        return "REQUEST";
    case MessageType::REQUEST_NO_RETURN:
        return "REQUEST_NO_RETURN";
    case MessageType::NOTIFICATION:
        return "NOTIFICATION";
    case MessageType::RESPONSE:
        return "RESPONSE";
    case MessageType::ERROR:
        return "ERROR";
    case MessageType::TP_REQUEST:
        return "TP_REQUEST";
    case MessageType::TP_REQUEST_NO_RETURN:
        return "TP_REQUEST_NO_RETURN";
    case MessageType::TP_NOTIFICATION:
        return "TP_NOTIFICATION";
    case MessageType::TP_RESPONSE:
        return "TP_RESPONSE";
    case MessageType::TP_ERROR:
        return "TP_ERROR";
    }
    return "UNKNOWN";
}

}  // namespace tc8::dissect
