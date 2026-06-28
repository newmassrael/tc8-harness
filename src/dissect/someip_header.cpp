#include "someip_header.h"

namespace tc8::dissect {

// The wire-constant enums now live in the neutral someip/protocol.h leaf;
// pull them into this TU so the parser code reads unqualified.
using someip::MessageType;
using someip::ReturnCode;

namespace {

std::uint16_t readBe16(const std::uint8_t *p) {
    return static_cast<std::uint16_t>((std::uint16_t(p[0]) << 8) | p[1]);
}

std::uint32_t readBe32(const std::uint8_t *p) {
    return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) | (std::uint32_t(p[2]) << 8) | std::uint32_t(p[3]);
}

}  // namespace

std::optional<ParseResult> parseSomeIpHeader(const std::uint8_t *data, std::size_t len) {
    if (len < 8) {
        return std::nullopt;
    }
    const std::uint32_t length_field = readBe32(data + 4);
    // length 는 message_id + length 이후 필드 크기 — 최소 8 (request_id + 4바이트).
    if (length_field < 8) {
        return std::nullopt;
    }
    const std::size_t total = static_cast<std::size_t>(length_field) + 8;
    if (len < total) {
        return std::nullopt;
    }

    ParseResult r{};
    r.header.service_id = readBe16(data + 0);
    r.header.method_id = readBe16(data + 2);
    r.header.length = length_field;
    r.header.client_id = readBe16(data + 8);
    r.header.session_id = readBe16(data + 10);
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
