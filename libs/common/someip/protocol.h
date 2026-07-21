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

// Service Discovery message magic. Every SD message carries a fixed Message ID
// (header Service ID + Method ID) per PRS_SOMEIPSD_00248 / PRS_SOMEIPSD_00249:
// Service ID 0xFFFF, Method ID 0x8100. Single source of truth for the two
// literals that were previously hand-spelled across the captured recognizers
// (someip_captured.h), the SD builder (someip_sd_builder.cpp), and the
// documentation-site exporter (decode_pcap_command.cpp).
inline constexpr std::uint16_t kSdServiceId = 0xFFFF;
inline constexpr std::uint16_t kSdMethodId  = 0x8100;

// Reserved Service ID for the DUT-side SD start() testability marker: a default-
// off DUT emits an OfferService entry for THIS service the instant it arms its
// Initial-Wait timer, so the tester has a self-identifying wire anchor for the
// internal start() reference (see SomeIpCaptured::is_sd_start_marker). It is a
// dedicated reserved id — no real service uses it — so the marker cannot be
// confused with a genuine Offer, and only a frame carrying it re-anchors the
// measurement (recognition by PRESENCE of this id, never by absence of entries).
// Distinct from the 0xFFFE unknown-service sentinel (sd_test_unknown::kServiceId)
// so the marker and the negative-axis "unknown service" cases never collide; a
// DUT vendor implementing the timing testability profile offers this id as its
// start signal.
inline constexpr std::uint16_t kSdStartMarkerServiceId = 0xFFFD;

// True when a SOME/IP header's Message ID is the Service Discovery magic. The
// captured recognizers gate SD payload parsing on the Service ID alone (the
// Method ID is implied once the frame is on the SD channel); consumers that see
// the whole header — the exporter's row classifier — check the full pair here.
inline constexpr bool isSdMessageId(std::uint16_t service_id, std::uint16_t method_id) {
    return service_id == kSdServiceId && method_id == kSdMethodId;
}

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
