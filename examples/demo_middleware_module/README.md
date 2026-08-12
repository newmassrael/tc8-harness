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
tc8::testability::ProtocolServer server{std::make_unique<tc8::dut::LinuxSocketBackend>()};
server.registerModule(std::make_unique<MyOemModule>(/* my config */));
server.start(/* port */);
```

The export splits the protocol core from its socket adapter so the *same* module
source builds against either backend — the engines are pure byte math and the I/O
goes through `net::SocketBackend`. Link targets:

| Target | Contents |
|---|---|
| `tc8::tc8_testability_core` | backend-agnostic protocol core — no socket syscalls |
| `tc8::tc8_linux_backend` | POSIX `SocketBackend` adapter |
| `tc8::tc8_testability_server` | convenience alias = `core` + `posix_backend` |
| `tc8::tc8_testability_client` | tester-side client — drives your module over the wire |

The full exported target set (including `tc8::tc8_wire` and the AUTOSAR engines)
is documented in the package's own `tc8-utm-config.cmake`, which `utm_export_smoke`
checks against the generated target list so it cannot drift.

### Driving your module from a tester

The hermetic `MiddlewareContext` test below exercises your module in-process. To
drive it the way a real tester does — over the wire, through the endpoint's
dispatch — link `tc8::tc8_testability_client` and call `testabilityCall()` with
your GID/PID; it is the same client the harness itself uses, so there is no
second framing implementation to keep in step. `examples/oem-utm-consumer` is a
worked end-to-end example.

### POSIX UTM

Link `tc8::tc8_testability_core` + `tc8::tc8_linux_backend` (or the
`tc8::tc8_testability_server` alias) and construct `LinuxSocketBackend` in `main()`,
as above.

### lwIP UTM (embedded)

Install the optional `utm-sdk-lwip` component alongside `utm-sdk`:

```
cmake --install <tc8-build> --component utm-sdk      --prefix <sdk>
cmake --install <tc8-build> --component utm-sdk-lwip --prefix <sdk>
```

**SDK surface** (`share/tc8-utm/lwip/`), shipped as source because it compiles
against *your* lwIP — the SDK ships the bridge to the seam, not the stack:

- `lwip_socket_backend.{h,cpp}` — the lwIP↔`SocketBackend` bridge
- `lwipopts_base.h` + `utm/lwipopts.h` — the UTM lwIP config: a product-neutral
  infrastructure base plus a tiny `utm/` layer adding `LWIP_IGMP` +
  `LWIP_MULTICAST_TX_OPTIONS` (required by `joinMulticast`/`leaveMulticast`) and
  lwIP's default assert. Point lwIP at `lwip/utm/` (its `lwipopts.h` includes
  `../lwipopts_base.h`). Not layered on the conformance config; a working reference.

**Example** (`share/tc8-utm/lwip/example/`), a replaceable starting point, not a
stable API:

- `lwip_stack_bringup.{h,cpp}` — `BringUpLwipStack(afterNetifUp = nullptr)`
  (threaded `tcpip_init`, unix-tapif netif, static address from `TC8_LWIP_*` env,
  RFC 6528 ISN seed) + `ParkUntilSigterm()`.

Bringing the stack up is the composition root's job and is target-specific, so it
is shipped as an example: it is **unix-port specific** (the OEM needs
`examples/example_app/default_netif.h` + the `tcp_isn` addon on its lwIP/contrib
include path), and a real embedded netif replaces it. It is **fault-free** — the
conformance fault seams stay in the in-tree DUT, installed via the `afterNetifUp`
callback a UTM never passes.

Your build compiles `lwip/lwip_socket_backend.cpp` (and, if reused,
`lwip/example/lwip_stack_bringup.cpp`) against your lwIP with `lwip/utm/` on the
include path, links `tc8::tc8_testability_core` (the backend-agnostic core — no
POSIX adapter) + the engines, and composes `main()`:

```cpp
tc8::lwip_dut::BringUpLwipStack();                 // example bring-up (or your own)
tc8::testability::ProtocolServer server{std::make_unique<tc8::lwip_dut::LwipSocketBackend>()};
server.registerModule(std::make_unique<MyOemModule>(/* my config */));
server.start(/* port */);
tc8::lwip_dut::ParkUntilSigterm();
```

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
