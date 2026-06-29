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

## TD-02 — Same C++/Python wire-decode mirror exists for the other TC8 protocols

**Status:** OPEN (accepted). **Logged:** 2026-06-29.

**What.** TD-01 resolved the duplication for SOME/IP-SD only. The identical
cross-language pattern remains for every other protocol on the TC8 surface:
the C++ harness hand-decodes each header in `src/sce_integration/*_captured.h`
(`arp_captured.h`, `ipv4_captured.h`, `icmpv4_captured.h`, `udp_captured.h`,
`tcp_captured.h`, `dhcpv4_captured.h`) and the site dissector
`site/scripts/decode_pcap.py` hand-decodes the same headers in its parallel
`_dissect_arp/_ipv4/_icmpv4/_udp/_tcp/_dhcpv4` functions. The offsets/widths are
mirrored by hand, same as SD was.

**Risk if left.** Same shape as TD-01, but lower probability: these are stable,
long-standardised headers (RFC 791/793/768/826/792, RFC 2131) that rarely
change, whereas SD carries the vendor-extensible bit-sliced fields that actually
drifted. A miss is still a silent site-preview divergence, not a verdict error
(the C++ stays authoritative).

**Textbook fix (deferred — incremental).** Extend the SD mechanism now proven in
TD-01: one `*_wire.def` per protocol (or a shared `tc8_wire.def`), `#include`d by
the C++ `*_captured.h` and consumed by `tools/gen_*_wire.py` to generate the
`decode_pcap` dissector bodies, each behind a `--check` freshness + golden-vector
gate. The SD `.def` + `tools/gen_someip_sd_wire.py` + the X-macro support header
`someip_sd_wire.h` are the template.

**Why deferred.** Proportionality: SD was the one that bit, and it is now closed.
The remaining headers are low-drift, so converting them is worthwhile for
uniformity but not urgent. Doing them one protocol at a time keeps each change
reviewable. Pick up arp/ipv4/udp/tcp/icmpv4/dhcpv4 in that rough order of how
often each header's decode is touched.
