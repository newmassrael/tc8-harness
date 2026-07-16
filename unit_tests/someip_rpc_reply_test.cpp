#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/someip_rpc_builder.h"

namespace tc8::stimulus {
namespace {

// Identity of a Method Request the DUT (client role) would send to the
// tester-server in the client-role topology. Non-default client_id/session_id
// so the echo-into-reply assertions catch a swapped or dropped Request ID.
// service/method mirror tc8-dut's echoUINT8 (the reply carries the same
// Message ID per SOME/IP Request ID semantics).
SomeIpRpcMessage makeCapturedRequest() {
    SomeIpRpcMessage t{};
    t.service_id = 0xF4E7;
    t.method_id = 0x0008;
    t.client_id = 0x1234;   // DUT-assigned client id, echoed in the reply.
    t.session_id = 0x0007;  // DUT request session, echoed in the reply.
    t.interface_version = 0x01;
    t.payload = {0x42};     // one echoed UINT8 byte.
    return t;
}

TEST(BuildMethodResponse, MessageTypeIsResponseAndEchoesIds) {
    const auto b = buildMethodResponse(makeCapturedRequest());
    ASSERT_EQ(b.size(), 17u);  // 16-byte header + 1 payload byte.
    // Message ID echoed: service 0xF4E7, method 0x0008.
    EXPECT_EQ(b[0], 0xF4u);
    EXPECT_EQ(b[1], 0xE7u);
    EXPECT_EQ(b[2], 0x00u);
    EXPECT_EQ(b[3], 0x08u);
    // Length = 8 (Request ID..return_code) + 1 payload byte = 9.
    EXPECT_EQ(b[4], 0x00u);
    EXPECT_EQ(b[5], 0x00u);
    EXPECT_EQ(b[6], 0x00u);
    EXPECT_EQ(b[7], 0x09u);
    // Request ID echoed: client 0x1234, session 0x0007.
    EXPECT_EQ(b[8], 0x12u);
    EXPECT_EQ(b[9], 0x34u);
    EXPECT_EQ(b[10], 0x00u);
    EXPECT_EQ(b[11], 0x07u);
    // Proto=1, iface=1, msg_type=0x80 RESPONSE, return_code=0x00 E_OK.
    EXPECT_EQ(b[12], 0x01u);
    EXPECT_EQ(b[13], 0x01u);
    EXPECT_EQ(b[14], 0x80u);
    EXPECT_EQ(b[15], 0x00u);
    // Payload echoed back.
    EXPECT_EQ(b[16], 0x42u);
}

TEST(BuildMethodError, MessageTypeIsErrorWithExplicitReturnCode) {
    SomeIpRpcMessage t = makeCapturedRequest();
    t.return_code = ::tc8::someip::ReturnCode::E_NOT_OK;  // E_NOT_OK — PRS_SOMEIP_00757: Error must not be E_OK.
    t.payload.clear();     // Error replies carry no method payload here.
    const auto b = buildMethodError(t);
    ASSERT_EQ(b.size(), 16u);
    // Length = 8 (no payload).
    EXPECT_EQ(b[7], 0x08u);
    // msg_type=0x81 ERROR, return_code=0x01 E_NOT_OK.
    EXPECT_EQ(b[14], 0x81u);
    EXPECT_EQ(b[15], 0x01u);
}

TEST(BuildMethodError, DefaultReturnCodeLeftAsEOkForNegativeDrive) {
    // The wrapper does NOT auto-correct return_code, so a negative case can
    // drive the spec-forbidden Error(0x81)+E_OK(0x00) shape deliberately.
    SomeIpRpcMessage t = makeCapturedRequest();
    t.payload.clear();
    const auto b = buildMethodError(t);  // return_code left at struct default 0x00.
    ASSERT_GE(b.size(), 16u);
    EXPECT_EQ(b[14], 0x81u);
    EXPECT_EQ(b[15], 0x00u);
}

TEST(BuildMethodReply, LengthOverrideDrivesMalformedReply) {
    SomeIpRpcMessage t = makeCapturedRequest();
    t.length_override = 0xFFu;  // claim more bytes than the datagram delivers.
    const auto b = buildMethodResponse(t);
    ASSERT_GE(b.size(), 8u);
    EXPECT_EQ(b[4], 0x00u);
    EXPECT_EQ(b[5], 0x00u);
    EXPECT_EQ(b[6], 0x00u);
    EXPECT_EQ(b[7], 0xFFu);
}

TEST(BuildMethodResponse, ForcesMessageTypeOverPreSetTpRequest) {
    // The wrapper must FORCE message_type to RESPONSE, not OR/merge into it.
    // Starting from a TP_REQUEST (0x20, TP-Flag set) the Response byte must be
    // 0x80, not 0xA0 (TP_RESPONSE) — proving the force overwrites and clears
    // the TP-Flag rather than leaving it set.
    SomeIpRpcMessage t = makeCapturedRequest();
    t.message_type = ::tc8::someip::MessageType::TP_REQUEST;  // 0x20
    const auto b = buildMethodResponse(t);
    ASSERT_GE(b.size(), 16u);
    EXPECT_EQ(b[14], 0x80u);  // RESPONSE, not 0xA0.
}

TEST(BuildMethodRequest, DefaultsEmitRequestEOk) {
    // Direct coverage of the SSOT header core (every reply builder and ~117
    // cases route through it). Defaults: REQUEST (0x00) / E_OK (0x00).
    const auto b = buildMethodRequest(SomeIpRpcMessage{});
    ASSERT_EQ(b.size(), 16u);  // default payload is empty.
    EXPECT_EQ(b[14], 0x00u);
    EXPECT_EQ(b[15], 0x00u);
}

TEST(BuildMethodRequest, RequestNoReturnEmits0x01) {
    SomeIpRpcMessage t{};
    t.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;
    const auto b = buildMethodRequest(t);
    ASSERT_GE(b.size(), 16u);
    EXPECT_EQ(b[14], 0x01u);
}

TEST(BuildMethodRequest, OverridesEmitRawOffEnumBytes) {
    // The *_override fields emit a raw byte the enum cannot represent, for
    // negative cases (reserved message_type 0x07, off-enum return_code 0xC0).
    SomeIpRpcMessage t{};
    t.message_type_override = 0x07u;
    t.return_code_override = 0xC0u;
    const auto b = buildMethodRequest(t);
    ASSERT_GE(b.size(), 16u);
    EXPECT_EQ(b[14], 0x07u);
    EXPECT_EQ(b[15], 0xC0u);
}

TEST(BuildMethodRequest, OverrideBeatsTypedField) {
    // When both are set the override wins — it is the escape hatch, so a
    // negative case can emit any byte regardless of the typed field.
    SomeIpRpcMessage t{};
    t.message_type = ::tc8::someip::MessageType::REQUEST;  // would emit 0x00
    t.message_type_override = 0x99u;                       // but this wins
    const auto b = buildMethodRequest(t);
    ASSERT_GE(b.size(), 16u);
    EXPECT_EQ(b[14], 0x99u);
}

// emitMethodReply's defining property: the reply is delivered intact and
// originates from the tester's SERVICE port (not an ephemeral one), the way a
// server answers a client. Loopback round-trip, no DUT required.
TEST(EmitMethodReply, DeliversReplyFromServicePort) {
    // Stand in for the DUT client: a loopback UDP socket the reply lands on.
    const int rx = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(rx, 0);
    sockaddr_in ra{};
    ra.sin_family = AF_INET;
    ra.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ra.sin_port = 0;  // kernel picks the client port.
    ASSERT_EQ(::bind(rx, reinterpret_cast<sockaddr *>(&ra), sizeof(ra)), 0);
    sockaddr_in bound{};
    socklen_t bl = sizeof(bound);
    ASSERT_EQ(::getsockname(rx, reinterpret_cast<sockaddr *>(&bound), &bl), 0);
    const std::uint16_t client_port = ntohs(bound.sin_port);
    timeval tv{1, 0};  // bounded recv so a drop fails instead of hanging.
    ::setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    const auto reply = buildMethodResponse(makeCapturedRequest());
    const std::uint16_t kServicePort = 30509;  // tester's offered service port.
    const int rc = emitMethodReply("lo", reply, kServicePort,
                                   MethodEndpoint{htonl(INADDR_LOOPBACK), client_port});
    ASSERT_EQ(rc, 0);

    std::uint8_t buf[64] = {};
    sockaddr_in from{};
    socklen_t fl = sizeof(from);
    const ssize_t n = ::recvfrom(rx, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&from), &fl);
    ::close(rx);
    ASSERT_EQ(n, static_cast<ssize_t>(reply.size()));
    EXPECT_EQ(std::vector<std::uint8_t>(buf, buf + n), reply);
    EXPECT_EQ(ntohs(from.sin_port), kServicePort);
}

// --- Event Notification (message type 0x02) — tester SERVER-role delivery ---

// Identity of an event the tester-server pushes to a subscribed DUT: method_id
// is the event ID (high bit set), client_id stays 0 (a notification carries no
// Request ID), payload is the serialised event value.
SomeIpRpcMessage makeEvent() {
    SomeIpRpcMessage t{};
    t.service_id = 0xF4E7;
    t.method_id = 0x8001;   // TestEventUINT8 — event ID, high bit set.
    t.session_id = 0x0005;  // server event session counter.
    t.payload = {0x42};     // one event byte.
    return t;
}

TEST(BuildEventNotification, MessageTypeIsNotificationWithEventId) {
    const auto b = buildEventNotification(makeEvent());
    ASSERT_EQ(b.size(), 17u);  // 16-byte header + 1 payload byte.
    // Message ID: service 0xF4E7, event/method 0x8001.
    EXPECT_EQ(b[0], 0xF4u);
    EXPECT_EQ(b[1], 0xE7u);
    EXPECT_EQ(b[2], 0x80u);
    EXPECT_EQ(b[3], 0x01u);
    // Length = 8 + 1 payload = 9.
    EXPECT_EQ(b[7], 0x09u);
    // Request ID: client 0x0000 (notification has none), session 0x0005.
    EXPECT_EQ(b[8], 0x00u);
    EXPECT_EQ(b[9], 0x00u);
    EXPECT_EQ(b[10], 0x00u);
    EXPECT_EQ(b[11], 0x05u);
    // Proto=1, iface=1, msg_type=0x02 NOTIFICATION, return_code=0x00 E_OK.
    EXPECT_EQ(b[14], 0x02u);
    EXPECT_EQ(b[15], 0x00u);
    EXPECT_EQ(b[16], 0x42u);  // event payload.
}

TEST(BuildEventNotification, ForcesNotificationOverPreSetTpNotification) {
    // The wrapper must FORCE message_type to NOTIFICATION (0x02), clearing the
    // TP-Flag — starting from TP_NOTIFICATION (0x22) the byte must be 0x02.
    SomeIpRpcMessage t = makeEvent();
    t.message_type = ::tc8::someip::MessageType::TP_NOTIFICATION;  // 0x22
    const auto b = buildEventNotification(t);
    ASSERT_GE(b.size(), 16u);
    EXPECT_EQ(b[14], 0x02u);
}

// emitEventNotification delivers the event from the tester's SERVICE (event)
// port to the subscribed DUT endpoint — same server->client transport as
// emitMethodReply. Loopback round-trip, no DUT required.
TEST(EmitEventNotification, DeliversNotificationFromServicePort) {
    const int rx = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(rx, 0);
    sockaddr_in ra{};
    ra.sin_family = AF_INET;
    ra.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ra.sin_port = 0;  // kernel picks the subscribed-client port.
    ASSERT_EQ(::bind(rx, reinterpret_cast<sockaddr *>(&ra), sizeof(ra)), 0);
    sockaddr_in bound{};
    socklen_t bl = sizeof(bound);
    ASSERT_EQ(::getsockname(rx, reinterpret_cast<sockaddr *>(&bound), &bl), 0);
    const std::uint16_t client_port = ntohs(bound.sin_port);
    timeval tv{1, 0};
    ::setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    const auto notif = buildEventNotification(makeEvent());
    const std::uint16_t kEventPort = 30510;  // tester's offered event source port.
    const int rc = emitEventNotification("lo", notif, kEventPort,
                                         MethodEndpoint{htonl(INADDR_LOOPBACK), client_port});
    ASSERT_EQ(rc, 0);

    std::uint8_t buf[64] = {};
    sockaddr_in from{};
    socklen_t fl = sizeof(from);
    const ssize_t n = ::recvfrom(rx, buf, sizeof(buf), 0, reinterpret_cast<sockaddr *>(&from), &fl);
    ::close(rx);
    ASSERT_EQ(n, static_cast<ssize_t>(notif.size()));
    EXPECT_EQ(std::vector<std::uint8_t>(buf, buf + n), notif);
    EXPECT_EQ(ntohs(from.sin_port), kEventPort);
}

// packSomeIpMessages — the multiple-SOME/IP-in-one-L4-packet enabler (two
// messages in one UDP datagram or TCP segment). Pure concatenation in order; the
// caller's per-message length_override drives any unalignment.
TEST(PackSomeIpMessages, ConcatenatesMessagesInOrder) {
    const auto a = buildEventNotification(makeEvent());
    SomeIpRpcMessage second = makeEvent();
    second.session_id = 0x0006;
    second.payload = {0x99};
    const auto b = buildEventNotification(second);

    const auto packed = packSomeIpMessages({a, b});
    ASSERT_EQ(packed.size(), a.size() + b.size());
    EXPECT_EQ(std::vector<std::uint8_t>(packed.begin(), packed.begin() + a.size()), a);
    EXPECT_EQ(std::vector<std::uint8_t>(packed.begin() + a.size(), packed.end()), b);
}

TEST(PackSomeIpMessages, EmptyInputYieldsEmpty) {
    EXPECT_TRUE(packSomeIpMessages({}).empty());
}

}  // namespace
}  // namespace tc8::stimulus
