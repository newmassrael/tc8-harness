# Vendor-neutral AUTOSAR engines (src/autosar/) — the public mechanisms a
# separate, private OEM UTM repo composes with its own config. Every engine is
# the same shape: a dependency-light STATIC lib (pure byte math — no syscalls,
# no third-party deps, no OEM content) with include/ (the tc8/autosar/ headers)
# as its sole PUBLIC root and the strict first-party warning set. tc8_add_engine
# is the single home for that recipe so adding an engine is one line and the lib
# pattern never drifts across copies. The install/EXPORT interface for each
# engine is wired once in the top-level TC8_UTM_INSTALL block.
#
# Each engine also joins TC8_UTM_ENGINES, the single list the UTM export iterates;
# this dir propagates that list to the parent scope at the end so the export
# cannot drift from the build.
function(tc8_add_engine name)
    add_library(${name} STATIC ${ARGN})
    # Every engine's public header (tc8/autosar/*.h) and every include its .cpp
    # reaches live under include/tc8/autosar/ — all namespaced — so include/ is the
    # sole PUBLIC root; no engine reaches through the flat src/ tree.
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)
    tc8_enable_strict_warnings(${name})
    # Record the engine in the single list the UTM export iterates, so adding an
    # engine stays one line and the install/EXPORT never drifts from the build.
    set(TC8_UTM_ENGINES ${TC8_UTM_ENGINES} ${name} PARENT_SCOPE)
endfunction()

# tc8::crypto — AES-CMAC (FIPS-197 AES-128 + RFC 4493), the SecOC MAC primitive.
# Keys are passed per call by the caller, so no keying material lives here.
tc8_add_engine(tc8_crypto aes_cmac.cpp)

# tc8::pn — AUTOSAR Partial Networking relevance filter: a bitwise AND of the
# received PNC bit vector with the ECU's cluster mask. Range location and
# cluster membership are injected config.
tc8_add_engine(tc8_pn pn_filter.cpp)

# tc8::crc — AUTOSAR CRC Routines (CRC-8/SAE-J1850 + CRC-16/CCITT-FALSE), the
# shared primitive the E2E profiles compose. Its own module so each CRC consumer
# links one verified implementation rather than re-deriving it.
tc8_add_engine(tc8_crc crc.cpp)

# tc8::e2e — AUTOSAR FO PRS E2EProtocol protect/check. Composes tc8::crc for the
# CRC; profile/Data ID/offset are injected config. Links tc8_crc.
tc8_add_engine(tc8_e2e e2e.cpp)
target_link_libraries(tc8_e2e PUBLIC tc8_crc)

# tc8::com — AUTOSAR SWS COM signal pack/unpack into I-PDUs (Intel + Motorola
# bit layout). Signal/PDU database is injected config.
tc8_add_engine(tc8_com com.cpp)

# tc8::nm — AUTOSAR Network Management state machine (SWS UDPNetworkManagement).
# State logic only; timings/layout/node id are injected config, and the owning
# module drives it via mainFunction()/rxNmPdu() and onTransmit.
tc8_add_engine(tc8_nm nm.cpp)

# tc8::someiptp — AUTOSAR SOME/IP-TP transport (PRS_SOMEIP §4.2.1.4): segment a
# large SOME/IP message into TP segments and reassemble received ones. Wire framing
# only; OEM ids and any connection lifecycle are the owning module's config.
tc8_add_engine(tc8_someiptp someiptp.cpp)

# Propagate the engine list to the top-level scope so the TC8_UTM_INSTALL export
# block (install(TARGETS ... ${TC8_UTM_ENGINES})) iterates the same set the build
# defined — one list, no drift.
set(TC8_UTM_ENGINES ${TC8_UTM_ENGINES} PARENT_SCOPE)
