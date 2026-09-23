# SCXML guard expressions — what the SCE rewriter accepts

A case's `cond="cpp:..."` guards and `<sce:use>` template parameters are C++
expressions over two Named Contexts, `captured` and `expected`. SCE's code
generator does not parse them as C++; it rewrites a small set of tokens and
passes the rest through. The shapes below follow from that, and several
headers in this repository are laid out the way they are because of it.

## The rewrite

`captured.X` becomes `this->captured_->X`, and `expected.X` becomes
`this->expected_->X`. That is the whole rule. Checked against the generated
`build/src/harness/generated/<case>_sm.inl`, for example:

    captured.payload_equals(::tc8::sce::ipv4::reassembly::reassembly11EchoData())
    → this->captured_->payload_equals(::tc8::sce::ipv4::reassembly::reassembly11EchoData())

What follows from it:

- **A method call works like a field.** `captured.method(args)` is rewritten
  the same way, so any check that is more than `==`, `!=` or arithmetic —
  a byte comparison, a bit test, a quoted-header match, a derived boolean — is
  written as a member function of the Captured (or Expected) struct.
  `Icmpv4Captured::payload_equals` and `quotes_ip_id` are this shape.
- **A bare `captured` is not rewritten.** Passing the context to a free
  function, `::tc8::check(captured, ...)`, leaves the identifier as written and
  fails to compile (`'captured' was not declared in this scope; did you mean
  'captured_'?`). Make the function a member instead.
- **One dot only.** `captured.X.Y` is not rewritten. So a Named Context never
  holds its fields in a nested member. It INHERITS them from data-only bases,
  and an inherited member is reached single-dot and rewritten like any other
  (`this->expected_->payload_view` comes from the `ExpectedPayload` base). The
  captured mixins (`captured_l3_endpoints.h`, `captured_l4_ports.h`,
  `captured_payload_snapshot.h`, `captured_frame_timing.h`,
  `captured_ip_fragmentation.h`) and the `*Expected : *Expectations` contexts
  are built this way for that reason. The bases are public, non-virtual and
  data-only, so the context stays a C++17 aggregate and `Expected{}` still
  value-initialises.
- **Everything else passes through verbatim**, including namespace-qualified
  `inline constexpr` constants and functions from this repository's headers
  (`::tc8::sce::tcp::kBasicsActiveLocalPort + 1U` parses as expected).
- **XML still applies.** A guard sits in an attribute, so `<` and `&` must be
  escaped (`&lt;`, `&amp;`), and an escaped expression does not survive being
  passed as a template parameter. Name the value with a function in a header
  and call that (`reassembly11EchoData()`), rather than spelling a
  `reinterpret_cast<...>` inline.

## Which headers a guard can see

The generated `<case>_sm.h` includes only the headers named by `cpp:include`
on the case's `<sce:context>` elements. A constant or function from any other
header reaches the guard only because the case's traits header
(`src/sce_integration/include/sce_integration/cases/<case>.h`) includes that
header BEFORE the generated state-machine header. Every case is compiled
through its traits header, so this holds, but the generated header is not
self-contained. A new helper a guard calls must be included by the traits.
