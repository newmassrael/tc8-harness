#pragma once

#include <cstdint>

// TC8 v3.0 §5.1.4 Enhanced Testability Service (ETS) — spec-authoritative IDs.
// Source: OPEN Alliance Automotive Ethernet ECU Test Specification Layer 3-7
//   v3.0, 25.10.2019 — Tables 1 (Methods) and 2 (Events and Fields).

namespace tc8::ets {

// --- Methods (§5.1.4, Table 1) ---
inline constexpr std::uint16_t kMethodResetInterface                         = 0x01;
inline constexpr std::uint16_t kMethodSuspendInterface                       = 0x02;
inline constexpr std::uint16_t kMethodTriggerEventUINT8                      = 0x03;
inline constexpr std::uint16_t kMethodTriggerEventUINT8Array                 = 0x04;
inline constexpr std::uint16_t kMethodTriggerEventUINT8Reliable              = 0x05;
inline constexpr std::uint16_t kMethodTriggerEventUINT8E2E                   = 0x06;
inline constexpr std::uint16_t kMethodEchoUINT8                              = 0x08;
inline constexpr std::uint16_t kMethodEchoUINT8Array                         = 0x09;
inline constexpr std::uint16_t kMethodEchoUINT8RELIABLE                      = 0x0A;
inline constexpr std::uint16_t kMethodEchoUINT8E2E                           = 0x0B;
inline constexpr std::uint16_t kMethodEchoINT8                               = 0x0E;
inline constexpr std::uint16_t kMethodEchoFLOAT64                            = 0x12;
inline constexpr std::uint16_t kMethodEchoUTF8FIXED                          = 0x13;
inline constexpr std::uint16_t kMethodEchoUTF16FIXED                         = 0x14;
inline constexpr std::uint16_t kMethodEchoUTF8DYNAMIC                        = 0x15;
inline constexpr std::uint16_t kMethodEchoUTF16DYNAMIC                       = 0x16;
inline constexpr std::uint16_t kMethodEchoENUM                               = 0x17;
inline constexpr std::uint16_t kMethodEchoUNION                              = 0x19;
inline constexpr std::uint16_t kMethodCheckByteOrder                         = 0x1F;
inline constexpr std::uint16_t kMethodEchoCommonDatatypes                    = 0x23;
inline constexpr std::uint16_t kMethodClientServiceActivate                  = 0x2F;
inline constexpr std::uint16_t kMethodClientServiceDeactivate                = 0x30;
inline constexpr std::uint16_t kMethodClientServiceSubscribeEventgroup       = 0x32;
inline constexpr std::uint16_t kMethodEchoInt64                              = 0x34;
inline constexpr std::uint16_t kMethodEchoUINT8Array2Dim                     = 0x35;
inline constexpr std::uint16_t kMethodEchoStaticUINT8Array                   = 0x36;
inline constexpr std::uint16_t kMethodEchoUINT8ArrayMinSize                  = 0x37;
inline constexpr std::uint16_t kMethodTriggerEventUINT8Multicast             = 0x3A;
inline constexpr std::uint16_t kMethodClientServiceGetLastValueOfEventTCP    = 0x3B;
inline constexpr std::uint16_t kMethodClientServiceGetLastValueOfEventUDPUnicast   = 0x3C;
inline constexpr std::uint16_t kMethodClientServiceGetLastValueOfEventUDPMulticast = 0x3D;
inline constexpr std::uint16_t kMethodEchoUINT8Array8BitLength               = 0x3E;
inline constexpr std::uint16_t kMethodEchoUINT8Array16BitLength              = 0x3F;
inline constexpr std::uint16_t kMethodEchoBitfields                          = 0x41;

// --- Events (§5.1.4, Table 2) ---
inline constexpr std::uint16_t kEventTestEventUINT8          = 0x8001;
inline constexpr std::uint16_t kEventTestEventUINT8Array     = 0x8002;
inline constexpr std::uint16_t kEventTestEventUINT8Reliable  = 0x8003;
inline constexpr std::uint16_t kEventTestEventUINT8E2E       = 0x8004;
inline constexpr std::uint16_t kEventTestEventUINT8Multicast = 0x800B;

// --- Fields (§5.1.4, Table 2) — notify / getter / setter IDs ---
inline constexpr std::uint16_t kFieldInterfaceVersionNotify        = 0x8005;
inline constexpr std::uint16_t kFieldInterfaceVersionGetter        = 0x25;
inline constexpr std::uint16_t kFieldTestFieldUINT8Notify          = 0x8006;
inline constexpr std::uint16_t kFieldTestFieldUINT8Getter          = 0x26;
inline constexpr std::uint16_t kFieldTestFieldUINT8Setter          = 0x27;
inline constexpr std::uint16_t kFieldTestFieldUINT8ArrayNotify     = 0x8007;
inline constexpr std::uint16_t kFieldTestFieldUINT8ArrayGetter     = 0x28;
inline constexpr std::uint16_t kFieldTestFieldUINT8ArraySetter     = 0x29;
inline constexpr std::uint16_t kFieldTestFieldUINT8ReliableNotify  = 0x8008;
inline constexpr std::uint16_t kFieldTestFieldUINT8ReliableGetter  = 0x2A;
inline constexpr std::uint16_t kFieldTestFieldUINT8ReliableSetter  = 0x2B;

// --- Eventgroups (§5.1.4, Table 2 column headers) ---
inline constexpr std::uint16_t kEventgroupA = 0x0002;
inline constexpr std::uint16_t kEventgroupB = 0x0005;
inline constexpr std::uint16_t kEventgroupC = 0x0006;

}  // namespace tc8::ets
