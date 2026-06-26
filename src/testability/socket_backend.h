#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "net/socket_backend.h"
#include "testability/reactor.h"

namespace tc8::testability {

// The shared socket seam lives in tc8::net (src/net/socket_backend.h); the
// testability core speaks its endpoint type, so import the name here.
using net::Endpoint;

// The testability-specific extension of the shared socket seam
// (tc8::net::SocketBackend): the operations whose result is a PRS_TPSP
// service-primitive outcome rather than a raw socket value — CONFIGURE_SOCKET
// option application, the ICMP / ICMPv6 ECHO_REQUEST emit, and the ETH
// INTERFACE_UP / INTERFACE_DOWN link-state change. Kept off the generic net
// seam so that layer stays free of testability protocol vocabulary; the Upper
// Tester server, which has none of these primitives, depends on the generic
// base alone and reuses the very same adapters.
//
// It also implements IoMultiplexer (poll + createWaker, src/testability/reactor.h)
// — the narrow capability the per-module Reactor needs. Segregated this way, the
// Reactor depends only on IoMultiplexer (not this fat class), and the Upper Tester
// depends only on net::SocketBackend (not the multiplexer it never uses).
//
// This is the PORT (ports & adapters): it lives in its own header — separate from
// the ProtocolServer application that consumes it — so an adapter (POSIX / lwIP)
// includes only the interface it implements, never the application core.
class SocketBackend : public net::SocketBackend, public IoMultiplexer {
public:
    // CONFIGURE_SOCKET parameter application -> testability result id
    // (E_OK / E_NOK / E_NTF / E_INV). The supported parameter set is
    // backend-specific (a stack lacking an option answers E_NOK).
    virtual std::uint8_t configureOption(int fd, std::uint16_t param_id,
                                         const std::uint8_t *val, std::uint16_t len) = 0;

    // ICMP ECHO_REQUEST: emit the pre-built Echo body (framed by the core via
    // the shared tc8::wire builder) to `dst_be` through `ifname` (empty / "0"
    // = any) -> result id (E_OK / E_IIF on an unknown interface / E_NOK).
    virtual std::uint8_t sendIcmpEcho(const std::string &ifname, std::uint32_t dst_be,
                                      const std::uint8_t *body, std::size_t len) = 0;

    // ICMPv6 ECHO_REQUEST: the IPv6 sibling of sendIcmpEcho — `dst16` is the
    // 16-byte destination in wire order. A stack built without IPv6 answers
    // E_NOK (surfaced, not silently dropped).
    virtual std::uint8_t sendIcmpv6Echo(const std::string &ifname, const std::uint8_t *dst16,
                                        const std::uint8_t *body, std::size_t len) = 0;

    // ETH INTERFACE_UP / INTERFACE_DOWN (PRS_TPSP §6.10): bring the named
    // interface administratively up (`up` = true) or down (`up` = false) ->
    // result id (E_OK / E_IIF on an unknown interface / E_NOK where the change
    // is not permitted, e.g. lacking the privilege to alter link state).
    virtual std::uint8_t setInterfaceUp(const std::string &ifname, bool up) = 0;

    // IP STATIC_ADDRESS (PRS_TPSP §6.10): assign IPv4 `addr_be` (network byte
    // order) with the `cidr`-bit netmask to `ifname` -> result id (E_OK / E_IIF on
    // an unknown interface / E_NOK where not permitted, e.g. lacking privilege).
    virtual std::uint8_t setStaticAddressV4(const std::string &ifname, std::uint32_t addr_be,
                                            std::uint8_t cidr) = 0;

    // IP STATIC_ROUTE (PRS_TPSP §6.10): add a non-persistent route to IPv4
    // `subnet_be`/`cidr` via `gateway_be` (all network byte order) on `ifname` ->
    // result id (E_OK / E_IIF on an unknown interface / E_NOK where not supported,
    // e.g. a single-homed stack with no routing table).
    virtual std::uint8_t setStaticRouteV4(const std::string &ifname, std::uint32_t subnet_be,
                                          std::uint8_t cidr, std::uint32_t gateway_be) = 0;

    // IPv6 STATIC_ADDRESS (PRS_TPSP §6.10, GID 0x06): the IPv6 sibling of
    // setStaticAddressV4 — assign the 16-byte `addr16` (wire order) with the
    // `prefix`-bit length to `ifname` -> result id (E_OK / E_IIF on an unknown
    // interface / E_NOK where not permitted or the stack lacks IPv6).
    virtual std::uint8_t setStaticAddressV6(const std::string &ifname, const std::uint8_t *addr16,
                                            std::uint8_t prefix) = 0;

    // IPv6 STATIC_ROUTE (PRS_TPSP §6.10, GID 0x06): the IPv6 sibling of
    // setStaticRouteV4 — add a non-persistent route to `subnet16`/`prefix` via
    // `gateway16` (all 16-byte wire order) on `ifname` -> result id (E_OK / E_IIF on
    // an unknown interface / E_NOK where unsupported, e.g. a stack with no IPv6
    // routing table).
    virtual std::uint8_t setStaticRouteV6(const std::string &ifname, const std::uint8_t *subnet16,
                                          std::uint8_t prefix, const std::uint8_t *gateway16) = 0;
};

}  // namespace tc8::testability
