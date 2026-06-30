# Tech-debt register

Known, accepted technical debt in tc8-harness. Each entry records WHAT the debt
is, WHY it exists, the RISK if left, the textbook FIX, and why it is DEFERRED.
This is a deliberate-deferral log, not a TODO list for unfinished features —
every item here is a working compromise with a documented escape path.

Entry format: a `## TD-NN` heading, then the fields below. Append new entries;
do not renumber. Reference an entry from code with a one-line pointer comment
(`see docs/tech-debt.md TD-NN`) at each coupled site so an editor of one site
discovers the others.

---

## TD-01 — SOME/IP-SD wire decode duplicated across C++ harness and Python site tooling

**Status:** RESOLVED (2026-06-29). **Logged:** 2026-06-29. Retained because the
in-code pointers (`see docs/tech-debt.md TD-01`) now resolve here for the
rationale behind the shared SSOT.

**What (the original debt).** The byte-level decode of SOME/IP-SD
entries/options was implemented independently in three places that had to agree
bit-for-bit:

- C++ — `src/sce_integration/someip_captured.h` (`decodeSdEntry`,
  `parseSdHeaderInto`, `parseSdOptionsInto`). Authoritative: drives conformance
  verdicts.
- Python — `site/scripts/decode_pcap.py` (decodes a captured pcap to JSON).
- Python — `site/scripts/generate_messages.py` (a cond evaluator that synthesises
  the same field names so the documentation site can resolve SCXML guard
  expressions over a decoded message).

There is no shared source for the wire layout (field offsets/widths); each side
hand-mirrors it.

**Why it exists.** The harness is C++ (it runs the live verdicts); the rendered
documentation site (`https://newmassrael.github.io/tc8-harness/`) is a separate
Python toolchain that decodes the captured pcaps to JSON for display. The two
share no runtime and no code, so the wire layout is mirrored by hand.

**Risk if left.** A wire-layout change must be applied by hand in all three
places. A miss is a SILENT divergence, not a build break: `site/` is not in the
harness CMake build or ctest, and the Python decoders have no cross-check against
the C++ struct. The harness verdict stays correct (C++ is authoritative), but the
site preview renders stale/UNKNOWN field values for the affected guards.

**Surfaced by.** The `reserved_counter` -> `entry_reserved` + `counter` SD-entry
split (commit `7e7422a5`). The initial change updated only the C++ decoder; a
3-agent cold review caught that both Python mirrors still emitted the removed
`reserved_counter` and lacked `entry_reserved`. All three were then migrated
together — this debt entry records the structural coupling that made the miss
possible.

**Resolution.** The SD wire layout is now written exactly once, in
`src/sce_integration/someip_sd_wire.def` (X-macro form). Every fixed-offset SD
field — header, entry common fields, both entry-type tails (including the
bit-sliced `num_opt1/2` nibbles and the `Reserved(12b)|Counter(4b)` split that
surfaced this debt), and the IPv4 option tail — is one row carrying its
`(offset, size, shift, mask)`. Both languages derive from it:

- C++ (authoritative) `#include`s the `.def` directly in
  `someip_captured.h`, expanding each row into a read against the shared
  `tc8::sd_wire::readBe` primitive — the same X-macro idiom `verdict.h` uses for
  `verdict_taxonomy.def`. The C++ decoder is a direct consumer of the SSOT, not
  a generated artifact, so it cannot drift from it.
- Python `tools/gen_someip_sd_wire.py` parses the same `.def` and generates the
  site mirror `site/scripts/someip_sd_wire_generated.py`, imported by
  `decode_pcap.py`.

This also collapses the gratuitous field-name divergence: the Python mirror now
emits the canonical C++ names (`index_first`, `num_opt1`, ...), so
`generate_messages.py` no longer remaps entry names for the SCXML cond view.

Drift is now structural, not a review burden:

- A wrong offset/width is impossible to apply to only one language — the layout
  is in one file both consume.
- `python3 tools/gen_someip_sd_wire.py --check` (CI `build-test`, alongside the
  `gen_verdict_taxonomy`/`gen_wire_manifest` gates) fails if the committed
  Python mirror is stale w.r.t. the `.def`, and also runs a golden-vector
  self-test that catches a wrong number in the `.def` itself (a value both
  languages would otherwise mirror consistently-but-wrong).
- The existing C++ `someip_captured_test` suite (which exercises
  `decodeSdEntry`/`parseSdHeaderInto`/`parseSdOptionsInto`) pins the C++ side
  bit-for-bit; it passed unchanged across the refactor.

---

## TD-02 — DHCPv4 BOOTP wire decode duplicated across C++ pipeline and Python site

**Status:** RESOLVED (2026-06-30). **Logged:** 2026-06-29 (originally as "the
other TC8 protocols"; scope corrected 2026-06-30 — see "Premise correction").

**What (the original debt).** After TD-01 closed SOME/IP-SD, the DHCPv4 BOOTP
fixed header was still hand-decoded in two places that had to agree byte-for-byte:
`src/dissect/packet_pipeline.cpp` (C++, authoritative — drives §4.7 verdicts) and
`site/scripts/decode_pcap.py` (`_dissect_dhcpv4`, the documentation-site mirror).
The offsets (op/htype/hlen/hops/xid/secs/flags, the four IPv4 addresses, chaddr,
the magic cookie, the options start) were mirrored by hand, same shape as SD was.

**Premise correction (2026-06-30).** The original entry claimed every non-SD TC8
protocol carried this C++/Python decode mirror. Direct inspection disproved that:
the C++ harness decodes ARP / IPv4 / ICMPv4 / UDP / TCP entirely through libtins
accessors (`ip->ttl()`, `tcp->seq()`, `arp->opcode()`, … in
`packet_pipeline.cpp`) — there are NO hand-coded byte offsets on the C++ side for
those five, so there is nothing to single-source; only the Python site dissector
hand-decodes them, and a `.def` with one consumer is not an SSOT. The lone
genuine C++/Python offset mirror was DHCPv4, because libtins does not dissect
BOOTP/DHCP. (The original entry also misnamed the C++ site as `*_captured.h`;
those headers only copy already-parsed `*Frame` fields — the decode is in the
dispatcher.) So TD-02 reduces to DHCPv4; the "other protocols" scope is WITHDRAWN
as mis-scoped, not deferred — there is no duplication there to fix.

**Resolution.** The BOOTP fixed-header layout now lives once in
`src/sce_integration/dhcpv4_wire.def` (X-macro form). Both languages derive from
it: C++ (authoritative) `#include`s it via `src/sce_integration/dhcpv4_wire.h`
(`decodeBootpFixedHeader` / `magicCookieValid`, called from
`packet_pipeline.cpp`), and `tools/gen_dhcpv4_wire.py` generates the Python site
mirror `site/scripts/dhcpv4_wire_generated.py` imported by `decode_pcap.py`. The
shared big-endian read primitive was lifted out of the SD support header into
`src/sce_integration/wire_read.h` (`::tc8::wire::readBe`) so both `.def` consumers
use one reader. Drift is now structural, same as TD-01:

- A wrong offset/width is impossible to apply to only one language.
- `python3 tools/gen_dhcpv4_wire.py --check` (CI `build-test`, alongside the
  `gen_someip_sd_wire`/`gen_wire_manifest` gates) fails on a stale mirror and runs
  a golden-vector self-test that catches a wrong number in the `.def` itself.
- `unit_tests/dhcpv4_wire_test.cpp` pins the C++ side bit-for-bit.

**Out of scope by design.** The post-cookie options TLV chain (code/length/value
walk: option 53 Message Type, Pad, END) has no fixed offsets, so it is decoded by
hand on each side and intentionally stays outside this offset SSOT; only the
options START offset is shared (`kOptionsOff`).

## TD-03 — `--expect` key strings hand-duplicated across producers and the consumer

**Status:** RESOLVED (2026-06-30). **Logged:** 2026-06-30.

**What (the original debt).** Every `--expect` field name was a bare string literal
repeated across the producers that derive it from `vsomeip.json`
(`tools/dut_identity.py` and the orchestrator `dut/env/orchestrator/src/dispatch.rs`),
the bash emitter (`dut/env/smoke-test.sh`), and the C++ consumer
(`src/cli/expect_parser.cpp`). A key thus lived as an unshared literal in 4–5
places, and a rename in one was not a compile error in bash/Python.

**Risk (the original).** Partially gated: the orchestrator parity-check diffs the
bash vs Rust `--expect` dumps, and `config_test.rs` asserts the Python keys match
the Rust struct — so a producer-side typo was caught. The genuine gap was the
CONSUMER: nothing mechanically tied `expect_parser.cpp`'s key strings to a
registry, so a rename OR omission there silently dropped the field to its `0`
sentinel and the SCXML guard then compared against 0 (a false-pass, not a crash).

**Resolution.** The `--expect` schema is now written once, in
`src/cli/tc8_expect_keys.def` (X-macro form): one row per key carrying its group,
the group's namespace prefix, and its value kind (U8/U16/U24/U32/IPV4/MAC/payload).
The consumer is GENERATED from it — `expect_parser.cpp` expands the `.def` to build
each group's lookup table — so it accepts exactly the registry's key set and can
neither drift from nor omit a key (the property TD-01's wire decoder has). Two
further guards make it textbook-safe:

- Type safety: every key's setter dereferences the target member by its real type
  (key == member name), and `applyField<KIND>` `static_assert`s the kind against
  the member type, so a row whose kind disagrees with the field is a compile error.
- Producer validation: `tools/check_expect_keys.py` (CI `build-test`, alongside the
  wire/verdict `.def` gates) parses the registry and fails if any hand-written
  producer (dispatch.rs / smoke-test.sh / dut_identity.py) emits a key absent from
  it — i.e. a key the generated consumer would silently drop.

The producers stay hand-written: they map keys to deployment VALUES (vsomeip.json
paths, bash vars), which is producer-specific and not the schema's concern. The
correct SSOT boundary is therefore "registry is authoritative for accepted keys
(consumer generated); producers validated against it", not full producer
generation. `unit_tests/expect_parser_test.cpp` pins the per-kind parse/range
behaviour across all seven groups.
