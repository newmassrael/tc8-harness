#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "someip/protocol.h"

namespace tc8::dissect {

struct SomeIpHeader {
    std::uint16_t service_id;
    std::uint16_t method_id;
    std::uint32_t length;
    std::uint16_t client_id;
    std::uint16_t session_id;
    std::uint8_t protocol_version;
    std::uint8_t interface_version;
    someip::MessageType message_type;
    someip::ReturnCode return_code;

    static constexpr std::size_t kHeaderSize = 16;
};

struct ParseResult {
    SomeIpHeader header;
    std::size_t total_size;
};

std::optional<ParseResult> parseSomeIpHeader(const std::uint8_t *data, std::size_t len);

const char *messageTypeName(someip::MessageType t);

}  // namespace tc8::dissect
