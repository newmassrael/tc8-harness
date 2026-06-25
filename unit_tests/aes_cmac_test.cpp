#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "autosar/aes_cmac.h"
#include "hex.h"

namespace tc8::crypto {
namespace {

using tc8::test::toHex;

// RFC 4493 §4: the example key K and the 64-byte example message M. Each example
// MACs a leading prefix of M, so one buffer covers all four cases.
constexpr std::array<std::uint8_t, 16> kKey = {{
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
}};

constexpr std::array<std::uint8_t, 64> kMsg = {{
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
}};

std::string cmacHex(std::size_t msg_len) {
    return toHex(aesCmac(kKey.data(), kKey.size(), kMsg.data(), msg_len));
}

// RFC 4493 Example 1: empty message. Also exercises the null-msg-at-zero-length
// contract (the empty prefix must never dereference the buffer).
TEST(AesCmacRfc4493, Example1EmptyMessage) {
    EXPECT_EQ(toHex(aesCmac(kKey.data(), kKey.size(), nullptr, 0)),
              "bb1d6929e95937287fa37d129b756746");
}

// RFC 4493 Example 2: a single whole block — last-block path via subkey K1.
TEST(AesCmacRfc4493, Example2OneBlock) {
    EXPECT_EQ(cmacHex(16), "070a16b46b4d4144f79bdd9dd04a287c");
}

// RFC 4493 Example 3: 40 bytes — a partial final block padded then XOR-ed with K2.
TEST(AesCmacRfc4493, Example3PartialFinalBlock) {
    EXPECT_EQ(cmacHex(40), "dfa66747de9ae63030ca32611497c827");
}

// RFC 4493 Example 4: 64 bytes — four whole blocks, last-block path via K1.
TEST(AesCmacRfc4493, Example4FourBlocks) {
    EXPECT_EQ(cmacHex(64), "51f0bebf7e3b9d92fc49741779363cfe");
}

// A key of any size other than AES-128's 16 bytes is a configuration error, not
// a silently truncated MAC (header contract).
TEST(AesCmacRfc4493, RejectsNon16ByteKey) {
    const std::vector<std::uint8_t> short_key(15, 0x00);
    const std::vector<std::uint8_t> long_key(32, 0x00);
    EXPECT_THROW(aesCmac(short_key.data(), short_key.size(), kMsg.data(), 16),
                 std::invalid_argument);
    EXPECT_THROW(aesCmac(long_key.data(), long_key.size(), kMsg.data(), 16),
                 std::invalid_argument);
}

}  // namespace
}  // namespace tc8::crypto
