# UTM SDK — middleware module template

This directory is the copy-from template for building an out-of-tree, OEM-specific
Upper Tester Module (UTM) on the `tc8-utm` SDK. `demo_module.{h,cpp}` is a
**synthetic** module (no OEM frames, ports, or keys) that composes the public
AUTOSAR engines and exercises the stateful middleware seam; copy it, replace the
fabricated configuration with your proprietary values, and wire it into your own
`main()`.

## The seam

A `tc8::testability::MiddlewareModule` is a stateful service group: unlike a
`registerPrimitive()` handler (request/response only) it holds state across
primitives and runs background activity. The host gives each module a dedicated
executor, so **every callback is serialized run-to-completion — module code needs
no locking.**

| Callback | When | Use |
|---|---|---|
| `groups()` | at `registerModule` | the GID(s) this module owns |
| `onStart(ctx)` | once, before serving | capture `ctx`, open sockets, arm timers |
| `onPrimitive(...)` | per request for an owned GID | fill `rid_out` + `resp_dat`; must not block |
| `onStartTest` / `onEndTest` | trace boundaries (PRS_TPSP §6.10.1) | reset to the inactive state |
| `onStop()` | once, at shutdown | release sockets/timers |

`MiddlewareContext` (injected at `onStart`) provides `backend()` (the shared
POSIX/lwIP socket adapter), `scheduleEvery`/`scheduleOnce`/`cancel` (timers on the
executor), and `emitEvent` (an asynchronous testability EVENT to the requester).

## Conventions

- **Reserved GID** — non-standard groups count down from `0x7F` (PRS_TPSP §6.6).
  The demo owns `0x7F`. A module may also override a built-in standard GID (the
  host consults modules before the built-in groups).
- **Non-blocking primitives** — `onPrimitive` must return promptly (PRS_TPSP §6.2):
  arm a timer or emit a later EVENT instead of waiting.
- **Engines, not values** — compose `tc8::nm`, `tc8::com`, `tc8::e2e`, `tc8::crc`,
  `tc8::crypto` (the public mechanisms); your proprietary frame layouts, signal
  database, timings, and keys are constructor/config inputs you supply, not part of
  this repository.

## Composing `main()` out-of-tree

Link the SDK via `find_package(tc8-utm)` (see `../oem-utm-consumer/`), then:

```cpp
tc8::testability::ProtocolServer server{std::make_unique<tc8::dut::PosixSocketBackend>()};
server.registerModule(std::make_unique<MyOemModule>(/* my config */));
server.start(/* port */);
```

The export splits the protocol core from its socket adapter so the *same* module
source builds against either backend — the engines are pure byte math and the I/O
goes through `net::SocketBackend`. Link targets:

| Target | Contents |
|---|---|
| `tc8::tc8_testability_core` | backend-agnostic protocol core — no socket syscalls |
| `tc8::tc8_posix_backend` | POSIX `SocketBackend` adapter |
| `tc8::tc8_testability_server` | convenience alias = `core` + `posix_backend` |

### POSIX UTM

Link `tc8::tc8_testability_core` + `tc8::tc8_posix_backend` (or the
`tc8::tc8_testability_server` alias) and construct `PosixSocketBackend` in `main()`,
as above.

### lwIP UTM (embedded)

Install the optional `utm-sdk-lwip` component alongside `utm-sdk`:

```
cmake --install <tc8-build> --component utm-sdk      --prefix <sdk>
cmake --install <tc8-build> --component utm-sdk-lwip --prefix <sdk>
```

It ships the lwIP↔seam bridge as **source** — `lwip_socket_backend.{h,cpp}` plus a
reference, layered `lwip/utm/lwipopts.h` — because the bridge must compile against
*your* (target-specific) lwIP stack; the SDK ships the bridge, not the stack. Your
build compiles `lwip/lwip_socket_backend.cpp` against your lwIP, links
`tc8::tc8_testability_core` (the backend-agnostic core — no POSIX adapter), and
swaps the backend in `main()`:

```cpp
tc8::testability::ProtocolServer server{std::make_unique<tc8::lwip_dut::LwipSocketBackend>()};
```

`LwipSocketBackend` requires `LWIP_IGMP` + `LWIP_MULTICAST_TX_OPTIONS`
(`joinMulticast`/`leaveMulticast`); the shipped `lwip/utm/lwipopts.h` turns these
on over the base config. The lwIP stack and your final `lwipopts.h` are yours — the
shipped file is a working reference, not a mandate.

## Configuration schema — the injection boundary

The config **struct shapes** are the schema; they live in the engine headers and
carry *no values*. A module is constructed with these structs populated from the
OEM's proprietary database — that population happens in the OEM repo, the single
place OEM data crosses into behavior.

| Engine | Config (shape only) |
|---|---|
| `tc8::crypto` | the AES-128 key buffer is passed per `aesCmac()` call — never stored |
| `tc8::pn` | `PnConfig{ pni_offset, pni_len }` |
| `tc8::e2e` | `Profile05Config{ data_id, offset, max_delta_counter }`, `Profile11Config{ data_id, data_id_mode, offset, max_delta_counter }` |
| `tc8::com` | `PduDef{ id, length, cycle, start_delay, send_type, signals }`, `SignalDef{ id, start_bit, bit_size, endian }` |
| `tc8::nm` | `Timing{ msg_cycle, msg_timeout, repeat_message, wait_bus_sleep }`, `PduLayout{ pdu_length, source_node_id_off, control_bit_vector_off, user_data_off, user_data_len }`, `node_id` |

`demo_module.cpp` fills every one of these with fabricated values — replace those
with your real configuration and nothing else in this repo changes.

## Status

The demo exercises every seam capability. Transmit + control: it ticks an NM
state machine, packs and E2E-protects a COM signal PDU cyclically, answers control
primitives, and emits a state-change EVENT. Receive: it binds a data socket and
registers it with `watchReadable`, so the executor's event-driven rx reactor
(`backend().poll` over the watched fds + a cross-thread waker — no drain timer)
delivers each inbound datagram on the module thread, where the COM engine unpacks
it; the unpacked value is exposed via an rx EVENT and a `GetLastSignal` primitive.

A hermetic test (`unit_tests/demo_module_test.cpp`) drives this module through a
fake `MiddlewareContext` and in-memory backend, with no network — including the rx
path by delivering a queued datagram to the watch handler. The pattern to copy for
testing your own module.
