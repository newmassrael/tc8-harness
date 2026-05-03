#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

namespace tc8::dissect {

enum class MessageType : std::uint8_t {
    REQUEST = 0x00,
    REQUEST_NO_RETURN = 0x01,
    NOTIFICATION = 0x02,
    RESPONSE = 0x80,
    ERROR = 0x81,
    TP_REQUEST = 0x20,
    TP_REQUEST_NO_RETURN = 0x21,
    TP_NOTIFICATION = 0x22,
    TP_RESPONSE = 0xA0,
    TP_ERROR = 0xA1,
};

enum class ReturnCode : std::uint8_t {
    E_OK = 0x00,
    E_NOT_OK = 0x01,
    E_UNKNOWN_SERVICE = 0x02,
    E_UNKNOWN_METHOD = 0x03,
    E_NOT_READY = 0x04,
    E_NOT_REACHABLE = 0x05,
    E_TIMEOUT = 0x06,
    E_WRONG_PROTOCOL_VERSION = 0x07,
    E_WRONG_INTERFACE_VERSION = 0x08,
    E_MALFORMED_MESSAGE = 0x09,
    E_WRONG_MESSAGE_TYPE = 0x0A,
};

struct SomeIpHeader {
    std::uint16_t service_id;
    std::uint16_t method_id;
    std::uint32_t length;
    std::uint16_t client_id;
    std::uint16_t session_id;
    std::uint8_t protocol_version;
    std::uint8_t interface_version;
    MessageType message_type;
    ReturnCode return_code;

    static constexpr std::size_t kHeaderSize = 16;
};

struct ParseResult {
    SomeIpHeader header;
    std::size_t total_size;
};

std::optional<ParseResult> parseSomeIpHeader(const std::uint8_t *data, std::size_t len);

const char *messageTypeName(MessageType t);

}  // namespace tc8::dissect
