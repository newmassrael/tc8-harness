#pragma once

#include <cstdint>

namespace tc8::someip {

// SOME/IP protocol invariants shared by the wire BUILDER (src/stimulus) and
// the wire PARSER (src/dissect). These are neutral protocol constants owned
// by neither layer, so both depend on this leaf header rather than one
// sibling reaching into the other.

// Message Type field (SOME/IP header byte 14) per PRS_SOMEIP_00055 /
// PRS_SOMEIP_00701. The TP variants set the 3rd-highest bit (0x20, the
// TP-Flag) per PRS_SOMEIP_00367.
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

// Return Code field (SOME/IP header byte 15) per PRS_SOMEIP_00058. The set of
// codes is PRS_SOMEIP_00191; the values allowed for a given message type are
// governed by PRS_SOMEIP_00757 (Response: any; Error: shall not be E_OK).
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

}  // namespace tc8::someip
