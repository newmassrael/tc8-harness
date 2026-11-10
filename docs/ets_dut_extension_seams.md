# ETS DUT — public floor and OEM extension seams

The Enhanced Testability Service (ETS) the reference DUT serves
(`dut/ets/ets.fidl`, `dut/ets/ets.fdepl`, `dut/dut_service/ets_*`) carries the
public OPEN Alliance TC8 v3.0 §5.1.4 surface only. An OEM's proprietary events,
methods and case ids live in the OEM's own repository and are injected through
the seams below. They are never copied into this one. That is the ETS half of
the repository's no-NDA invariant, which the `nda_hygiene` test and review
enforce.

## Layering

```
 OEM repo (private)   its fidl/fdepl superset (public + proprietary)  <- TC8_ETS_FIDL / TC8_ETS_FDEPL
                      its EtsImpl subclass                              <- TC8_ETS_FACTORY_SRC
                      its IEtsExtension                                 <- TC8_ETS_EXTENSION_SRC
                      its EmissionPolicy                                <- IEtsExtension::makeEmissionPolicy
                              | links against, never forks
 this repo (public)   public §5.1.4 ETS surface: EtsImpl, EmissionController + default
                      policy, no-op IEtsExtension, default factory
```

Public CI always builds the in-tree fidl, so the public floor is what this
repository conformance-tests.

## One injection idiom: compile-time source selection

Every seam is chosen at configure time by pointing a CMake cache variable at a
source file, the same idiom as `TC8_CASE_OVERRIDE_DIRS`:

| Variable | Replaces |
|---|---|
| `TC8_ETS_FIDL` / `TC8_ETS_FDEPL` | the interface definition (the O1 path below) |
| `TC8_ETS_FACTORY_SRC` | `createEtsStub()` — whole-stub replacement with an `EtsImpl` subclass |
| `TC8_ETS_EXTENSION_SRC` | `createEtsExtension()` — the `IEtsExtension` hooks (the O2 path) |

The defaults are plain strong functions. There are no weak symbols and no
environment flags, so an override cannot leak into a public conformance run.
Each variable is guarded with `if(NOT DEFINED ...)`, so a superproject's plain
`set()` survives CMP0126 OLD (cmake 3.16), where an unconditional `set()` would
wipe it. Each path gets an `EXISTS` check that fails at configure time.

## Two ways to add events and methods

CommonAPI can only fire an event its fidl declares, so an OEM extends the
service in one of two ways:

- **O1 — fidl override (primary).** Point `TC8_ETS_FIDL`/`TC8_ETS_FDEPL` at a
  superset of the public definition (same Service ID). Codegen emits the typed
  `fire...Event` calls, and the OEM's `EtsImpl` subclass uses them.
- **O2 — extension hook (raw injection).** `IEtsExtension::onRegister` /
  `onTick` / `onStop` receive an `IEtsEventSink` (`ets_event_sink.h`), whose
  `offerEvent` / `notify` / `onMethod` map onto vsomeip's `offer_event` /
  `notify` / `register_message_handler`. The sink wraps the SAME vsomeip
  application the CommonAPI service uses. It is fetched by CommonAPI's default
  connection id (the empty string, which is the key vsomeip stores it under),
  so there is no second routing client. A worked example and a hermetic test
  are `examples/demo_ets_extension/` and
  `unit_tests/demo_ets_extension_test.cpp`.

`IEtsClientControl` and `IEtsControlChannel` extend the same shared application
for the client role and for a Request/Response the DUT answers. The public
default extension uses neither.

## A field the public interface does not carry

An OEM's interface may have a field the public §5.1.4 table lacks. Its getter, setter and
notifier ids come from the OEM's own interface definition, so they are bound in the OEM's
`TC8_ETS_EXTENSION_SRC`, not here. What is shared is the serving logic, which has no vendor
content.

`serveUtf8DynamicField` (`ets_string_field.h`) serves a dynamic UTF-8 string field from
`onRegister`:

```cpp
void onRegister(EtsExtensionContext& ctx) override {
    field_ = serveUtf8DynamicField(ctx.sink, {kGetter, kSetter, kNotifier, {kEventgroup}}, "");
}
```

- The notifier is offered as a field (`IEtsEventSink::offerField`), so a subscriber gets the
  current value on its SubscribeEventgroupAck, and it is seeded with the initial value.
- The setter answers a Response with E_OK that carries the stored value, and the notifier
  fires when the value changes. A malformed request answers an Error with
  E_MALFORMED_MESSAGE and changes nothing.
- The wire shape is the one `echoUTF8DYNAMIC` uses: BE32 length, BOM, characters, NUL.
- The component is transport-blind. A Request that arrives over TCP is answered on that
  connection, and a Notification goes out over the transport the subscriber named in its
  SubscribeEventgroup. A field meant to be reliable needs the OEM's `vsomeip.json` to
  declare its eventgroup reliable; nothing here sets that.
- The extension keeps the returned field, and calls `reset` from its own reset path if the
  procedure expects the default value back after `resetInterface`.

## Emission

`EmissionController` (`ets_emission.h`) is the one engine behind every ETS
event. A source is either cyclic (free-running — `TestEventUINT8` 0x8001 at
250 ms, which existing cases depend on) or triggered: it fires only after its
`triggerEvent...` method, after `delay`, for `duration`, every `debounceTime`.
Because a triggered event never fires unsolicited, every must-not-send case
holds by construction.

The policy (`EmissionPolicy`) decides when a triggered source fires and which
value it carries. It receives the trigger method's three UInt32 arguments as
they arrived, and reads them with the `TriggerArgumentUnits` it was built with:
TC8 states only `start` in seconds and gives `duration` and `debounceTime` no
unit. Two policies are in-tree:

| | `DefaultTriggerPolicy` (the DUT's) | `SequentialTriggerPolicy` |
|---|---|---|
| units | `kDutTriggerUnits`: start and duration in seconds, debounceTime in milliseconds | as constructed |
| end of `duration` | inclusive; a zero duration fires one beat | exclusive, read after the debounce wait following each event; a zero duration fires nothing |
| values | per source, from 0, never reset | 1, 2, 3 for each trigger |
| a trigger during a running loop | replaces it | waits for it, then starts its own `start` from there |
| a late poll | drops the missed beats | emits the beat late, keeps the next on schedule |

`IEtsExtension::makeEmissionPolicy()` returns the policy the DUT installs before
emission starts (null keeps the default). `IEtsExtension::ets8001TriggerDriven()`
lets an OEM make 0x8001 triggered too; its default of false keeps the public
cyclic cadence byte-identical. `IEtsExtension::testFieldUint8InitialValue()` is
the value `TestFieldUINT8` is seeded with, and so the value of a subscriber's
initial Notification (0x42 by default; 0 is published too).

`suspendInterface` reads its `start` and `duration` in seconds, as TC8
§5.1.4.3.2 states them.

## Known gaps

- No test yet proves on the wire that a trigger method produces its
  Notification (and nothing without it), or that `TestFieldUINT8` sends initial
  data on SubscribeEventgroupAck. The logic is unit-tested
  (`unit_tests/ets_emission_test.cpp`).
- The event-to-eventgroup map is written in both `ets.fdepl` and
  `vsomeip.json`, and nothing asserts they agree.
