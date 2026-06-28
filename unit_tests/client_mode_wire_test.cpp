#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "client_mode_wire.h"

namespace tc8::dut {
namespace {

// Pins the DUT-side client-role Method Request wire layout (SOME/IP 16-byte
// header + payload), the firmware mirror of the tester's buildMethodRequest. A
// byte-offset regression here means tc8-dut would emit a malformed call the
// tester (or a real ECU's peer) could not dispatch.
TEST(ClientModeWire, MethodRequestHeaderLayout) {
    const std::vector<std::uint8_t> payload = {0x42};
    const auto b = buildMethodRequestWire(0xF4E8, 0x0008, 0x1234, 0x0007, 0x00, payload);
    ASSERT_EQ(b.size(), 17u);  // 16-byte header + 1 payload byte.
    EXPECT_EQ(b[0], 0xF4u);  // service_id 0xF4E8
    EXPECT_EQ(b[1], 0xE8u);
    EXPECT_EQ(b[2], 0x00u);  // method_id 0x0008
    EXPECT_EQ(b[3], 0x08u);
    EXPECT_EQ(b[4], 0x00u);  // length = 8 + 1 = 9
    EXPECT_EQ(b[5], 0x00u);
    EXPECT_EQ(b[6], 0x00u);
    EXPECT_EQ(b[7], 0x09u);
    EXPECT_EQ(b[8], 0x12u);  // client_id 0x1234
    EXPECT_EQ(b[9], 0x34u);
    EXPECT_EQ(b[10], 0x00u);  // session_id 0x0007
    EXPECT_EQ(b[11], 0x07u);
    EXPECT_EQ(b[12], 0x01u);  // protocol_version
    EXPECT_EQ(b[13], 0x01u);  // interface_version
    EXPECT_EQ(b[14], 0x00u);  // message_type REQUEST
    EXPECT_EQ(b[15], 0x00u);  // return_code E_OK
    EXPECT_EQ(b[16], 0x42u);  // payload
}

TEST(ClientModeWire, FireAndForgetNoPayload) {
    const auto b = buildMethodRequestWire(0xF4E8, 0x0008, 0, 1, 0x01, {});
    ASSERT_EQ(b.size(), 16u);
    EXPECT_EQ(b[7], 0x08u);   // length = 8 (no payload)
    EXPECT_EQ(b[14], 0x01u);  // RequestNoReturn
}

}  // namespace
}  // namespace tc8::dut
