#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace tc8::crypto {

// RFC 4493 AES-CMAC: the one-key CMAC of `msg` (msg_len bytes) under the
// AES-128 `key`, returning the full 128-bit tag.
//
// This is the vendor-neutral SecOC MAC building block (AUTOSAR SWS SecOC names
// CMAC-AES128 as an authentication algorithm). The *mechanism* — FIPS-197
// AES-128 plus the RFC 4493 subkey derivation and last-block handling — is a
// public standard and lives here. Everything proprietary stays with the caller:
// the key is passed by pointer per call and is never copied or retained by this
// repository, and tag truncation, freshness/counter inclusion, and the choice
// of which PDUs to authenticate are SecOC policy decided in the out-of-tree OEM
// module, not here.
//
// `key_len` must be 16 (RFC 4493 is defined over AES-128); any other length
// throws std::invalid_argument — keying material of the wrong size is a
// configuration error, never a silently truncated MAC. `msg` may be null only
// when `msg_len` is 0 (the empty-message case, RFC 4493 Example 1).
std::array<std::uint8_t, 16> aesCmac(const std::uint8_t* key, std::size_t key_len,
                                     const std::uint8_t* msg, std::size_t msg_len);

}  // namespace tc8::crypto
