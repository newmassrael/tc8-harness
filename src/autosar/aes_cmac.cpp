#include "tc8/autosar/aes_cmac.h"

#include <stdexcept>

namespace tc8::crypto {
namespace {

// ── FIPS-197 AES-128 (single-block ECB encrypt) ──
//
// Kept internal: AES-CMAC is the only public surface, and RFC 4493's published
// vectors exercise this block cipher transitively, so there is no reason to
// widen the API for a direct AES entry point. Nb = 4, Nk = 4, Nr = 10.

using Block = std::array<std::uint8_t, 16>;

// FIPS-197 Figure 7 substitution box.
constexpr std::array<std::uint8_t, 256> kSBox = {{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}};

// AES-128 key-expansion round constants (FIPS-197); index 1..10 are used.
constexpr std::array<std::uint8_t, 11> kRcon = {{
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
}};

// Multiply by x (0x02) in GF(2^8) modulo the AES polynomial 0x11b (FIPS-197).
constexpr std::uint8_t xtime(std::uint8_t a) {
    return static_cast<std::uint8_t>((a << 1) ^ ((a & 0x80U) ? 0x1bU : 0x00U));
}

// 176-byte expanded key (11 round keys of 16 bytes) per the FIPS-197 key schedule.
using RoundKeys = std::array<std::uint8_t, 176>;

RoundKeys expandKey(const std::uint8_t* key) {
    RoundKeys rk{};
    for (std::size_t i = 0; i < 16; ++i) {
        rk[i] = key[i];
    }
    // Each subsequent 4-byte word i (4..43) derives from words i-1 and i-4.
    for (std::size_t word = 4; word < 44; ++word) {
        std::uint8_t t0 = rk[4 * (word - 1) + 0];
        std::uint8_t t1 = rk[4 * (word - 1) + 1];
        std::uint8_t t2 = rk[4 * (word - 1) + 2];
        std::uint8_t t3 = rk[4 * (word - 1) + 3];
        if (word % 4 == 0) {
            // RotWord, then SubWord, then XOR the round constant into byte 0.
            const std::uint8_t rot = t0;
            t0 = kSBox[t1];
            t1 = kSBox[t2];
            t2 = kSBox[t3];
            t3 = kSBox[rot];
            t0 = static_cast<std::uint8_t>(t0 ^ kRcon[word / 4]);
        }
        rk[4 * word + 0] = static_cast<std::uint8_t>(rk[4 * (word - 4) + 0] ^ t0);
        rk[4 * word + 1] = static_cast<std::uint8_t>(rk[4 * (word - 4) + 1] ^ t1);
        rk[4 * word + 2] = static_cast<std::uint8_t>(rk[4 * (word - 4) + 2] ^ t2);
        rk[4 * word + 3] = static_cast<std::uint8_t>(rk[4 * (word - 4) + 3] ^ t3);
    }
    return rk;
}

void addRoundKey(Block& state, const RoundKeys& rk, std::size_t round) {
    for (std::size_t i = 0; i < 16; ++i) {
        state[i] = static_cast<std::uint8_t>(state[i] ^ rk[round * 16 + i]);
    }
}

void subBytes(Block& state) {
    for (auto& b : state) {
        b = kSBox[b];
    }
}

// Rows held in the column-major state s[r + 4*c]; row r rotates left by r.
void shiftRows(Block& state) {
    const Block in = state;
    for (std::size_t r = 1; r < 4; ++r) {
        for (std::size_t c = 0; c < 4; ++c) {
            state[r + 4 * c] = in[r + 4 * ((c + r) % 4)];
        }
    }
}

void mixColumns(Block& state) {
    for (std::size_t c = 0; c < 4; ++c) {
        const std::uint8_t a0 = state[4 * c + 0];
        const std::uint8_t a1 = state[4 * c + 1];
        const std::uint8_t a2 = state[4 * c + 2];
        const std::uint8_t a3 = state[4 * c + 3];
        state[4 * c + 0] = static_cast<std::uint8_t>(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
        state[4 * c + 1] = static_cast<std::uint8_t>(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
        state[4 * c + 2] = static_cast<std::uint8_t>(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
        state[4 * c + 3] = static_cast<std::uint8_t>((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}

Block aes128Encrypt(const RoundKeys& rk, const Block& in) {
    Block state = in;
    addRoundKey(state, rk, 0);
    for (std::size_t round = 1; round < 10; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, rk, round);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, rk, 10);
    return state;
}

// ── RFC 4493 AES-CMAC ──

// Left-shift a 128-bit big-endian block by one bit (RFC 4493 notation `<< 1`).
Block shiftLeftOne(const Block& in) {
    Block out{};
    std::uint8_t carry = 0;
    for (std::size_t i = 16; i-- > 0;) {
        out[i] = static_cast<std::uint8_t>((in[i] << 1) | carry);
        carry = static_cast<std::uint8_t>((in[i] & 0x80U) ? 1U : 0U);
    }
    return out;
}

// RFC 4493 §2.3 subkey: K' = (L << 1), XOR-ed with Rb (0x87 in the last byte)
// when the high bit of the input shifted out.
Block deriveSubkey(const Block& in) {
    Block out = shiftLeftOne(in);
    if (in[0] & 0x80U) {
        out[15] = static_cast<std::uint8_t>(out[15] ^ 0x87U);
    }
    return out;
}

}  // namespace

std::array<std::uint8_t, 16> aesCmac(const std::uint8_t* key, std::size_t key_len,
                                     const std::uint8_t* msg, std::size_t msg_len) {
    if (key_len != 16) {
        throw std::invalid_argument("tc8::crypto::aesCmac: RFC 4493 requires a 16-byte AES-128 key");
    }
    const RoundKeys rk = expandKey(key);

    // Step 1: subkeys K1, K2 from L = AES-128(key, 0^128).
    const Block zero{};
    const Block l = aes128Encrypt(rk, zero);
    const Block k1 = deriveSubkey(l);
    const Block k2 = deriveSubkey(k1);

    // Steps 2-3: block count and whether the final block is a whole block.
    const bool whole_last_block = (msg_len != 0) && (msg_len % 16 == 0);
    const std::size_t blocks = (msg_len == 0) ? 1 : (msg_len + 15) / 16;
    const std::size_t last_off = (blocks - 1) * 16;

    // Step 4: M_last = (final block) XOR K1 if whole, else padding(final) XOR K2.
    Block m_last{};
    if (whole_last_block) {
        for (std::size_t j = 0; j < 16; ++j) {
            m_last[j] = static_cast<std::uint8_t>(msg[last_off + j] ^ k1[j]);
        }
    } else {
        const std::size_t rem = msg_len - last_off;  // 0 only when msg_len == 0
        for (std::size_t j = 0; j < 16; ++j) {
            std::uint8_t b = 0x00;
            if (j < rem) {
                b = msg[last_off + j];
            } else if (j == rem) {
                b = 0x80;  // RFC 4493 padding: single 1 bit then zeros
            }
            m_last[j] = static_cast<std::uint8_t>(b ^ k2[j]);
        }
    }

    // Steps 5-7: CBC-MAC chain over the leading whole blocks, then M_last.
    Block x{};
    for (std::size_t i = 0; i + 1 < blocks; ++i) {
        for (std::size_t j = 0; j < 16; ++j) {
            x[j] = static_cast<std::uint8_t>(x[j] ^ msg[i * 16 + j]);
        }
        x = aes128Encrypt(rk, x);
    }
    for (std::size_t j = 0; j < 16; ++j) {
        x[j] = static_cast<std::uint8_t>(x[j] ^ m_last[j]);
    }
    return aes128Encrypt(rk, x);
}

}  // namespace tc8::crypto
