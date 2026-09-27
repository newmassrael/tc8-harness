#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "tc8/net/op_status.h"
#include "tc8/net/socket_backend.h"
#include "tc8/upper_tester_protocol.h"

namespace tc8::ut {

// OpConditionArpCache's static-entry pair (kArpConditionAddStatic /
// kArpConditionRemoveStatic, TC8 §4.2.3 DUT_CONFIGURE / CLEANUP), performed
// through the DUT's net::SocketBackend on the interface `ifname`.
//
// Platform-agnostic on purpose. Every stack this repository ships already
// implements the operation behind that seam (the lwIP backend via
// etharp_add_static_entry, the Linux one via RTM_NEWNEIGH NUD_PERMANENT), each
// with its own tests; what the 0x17 opcode adds is only the request parsing and
// the status mapping, and writing those once here keeps a second DUT that
// registers the opcode from growing its own spelling of either.
//
// `params` / `len` are the whole 0x17 request params (<action> <param:u16> ...).
// Returns false when `params[0]` is not a static-entry action, touching nothing,
// so a DUT's handler can try this first and fall through to its other actions.
inline bool applyArpStaticEntry(net::SocketBackend &backend, const std::string &ifname,
                                const std::uint8_t *params, std::size_t len,
                                std::uint8_t &status, std::vector<std::uint8_t> &body) {
    constexpr std::size_t kHead = 1 + 2;  // <action> <param:u16>
    if (len < 1) {
        return false;
    }
    const std::uint8_t action = params[0];
    if (action != kArpConditionAddStatic && action != kArpConditionRemoveStatic) {
        return false;
    }
    const bool add = action == kArpConditionAddStatic;
    if (len < kHead + 4 + (add ? 6U : 0U)) {
        status = kStatusMalformed;
        return true;
    }
    // Network byte order on the wire and in the backend's `addr_be`, so the four
    // bytes are copied as they stand rather than decoded and re-encoded.
    std::uint32_t addr_be = 0;
    std::memcpy(&addr_be, params + kHead, sizeof addr_be);
    const net::OpStatus op = add ? backend.addStaticNeighbor(ifname, addr_be, params + kHead + 4)
                                 : backend.removeNeighbor(ifname, addr_be);
    if (op == net::OpStatus::Ok) {
        status = kStatusOk;
    } else {
        status = kStatusNotPerformed;
        body.push_back(static_cast<std::uint8_t>(op));
    }
    return true;
}

}  // namespace tc8::ut
