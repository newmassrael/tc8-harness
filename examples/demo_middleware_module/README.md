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

The same module source compiles unchanged against the lwIP backend for an embedded
UTM (`tc8-lwip-utm`) — the engines are pure byte math and the I/O goes through
`net::SocketBackend`.

## Status

The demo is transmit + control only: it ticks an NM state machine, packs and
E2E-protects a COM signal PDU cyclically, answers control primitives, and emits a
state-change EVENT. Inbound PDU reception (`watchReadable`) is the one seam
capability still pending — it lands with the event-driven rx reactor.

A hermetic test (`unit_tests/demo_module_test.cpp`) drives this module through a
fake `MiddlewareContext` and in-memory backend, with no network — the pattern to
copy for testing your own module.
