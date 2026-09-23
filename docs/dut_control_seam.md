# DUT control seam — one case, any backend

## Goal

The harness drives a real ECU through the standard AUTOSAR Testability
protocol (PRS_TPSP; wire SSOT `include/tc8/testability_protocol.h`), and an OEM
runs the standard cases by configuration alone, with no code. A case therefore
talks to the DUT only through a backend-neutral seam
(`src/sce_integration/include/sce_integration/dut_control.h`,
`dut_socket_control.h`). The backend is chosen once per run by `--dut-control`:

| Backend | Talks to | Surface |
|---|---|---|
| `opcode` (default) | the reference tc8-dut's private Upper Tester (UDP 30600) | a TC8-specific superset |
| `testability` | any DUT serving AUTOSAR Testability (UDP 30700) | the portable standard subset |

The choice is global, not per case: every case of a run drives the same DUT.

## What the seam exposes: protocol operations, split by capability

The seam's operations are protocol-level: connect, accept, send and close a TCP
connection, send a UDP datagram, and so on. Each backend implements them with
its own wire (an opcode request, or a Testability service primitive such as
CREATE_AND_BIND + CONNECT). An active open carries a `BindSpec`, so a case
that pins the DUT's source port can still say so through the standard
primitives.

The operations are grouped into sub-interfaces by capability (`ITcpControl`,
`IUdpControl`, `ITcpStateProbe`, `ITcpRecvOob`, `IDhcpClientControl`,
`ILinkLocalControl`, `IUdpReceiveControl`, `IArpControl`). `IDutControl`
returns each one, or `nullptr` where the backend has no such capability. The
alternative, one fat interface whose unsupported calls return "unsupported",
was rejected: it hides the asymmetry below instead of stating it. Adapters are
thin. The encoding stays in the opcode builders
(`src/stimulus/upper_tester_client.*`) and the Testability free functions
(`include/tc8/testability_client.h`, `src/testability_client/`).

## The asymmetry is the standard's, and a case reports it as a skip

Some things a TC8 case needs have no Testability service primitive: reading
the kernel's TCP state (RTO, retransmission count), reading urgent data,
conditioning the ARP cache, starting link-local autoconf, and injecting
faults. Those exist only on the opcode backend. A case declares the
capabilities it needs (`kRequiredCapabilities`, `dut_capabilities.h`). On a
backend without them the centralised gate skips the case as not applicable,
before any stimulus runs, instead of letting it time out as a FAIL. Many TCP
cases are therefore not portable to a Testability DUT. That is a limit of the
standard, stated honestly, not a defect of the seam. This tree does not invent
wire primitives the standard does not define (see docs/tech-debt.md TD-16).

## How a case receives the seam

A case opts in with a stimulus overload that takes `IDutControl&`
(`test_case_traits.h` detects it). The CLI owns the backend and hands it to
`TestRunner::kickStimulus`. So the concrete backend headers are included only
by the CLI translation unit, not by the hundreds of case translation units.

## A decision recorded so it is not retaken

A listen-only case whose handshake completes leaves the Testability server an
accepted child socket and an accept Event that nobody collects, until
END_TEST. Silencing that with `LISTEN_AND_ACCEPT maxCon=0` as a "drain only"
mode was implemented and then rejected. PRS_TPSP defines `maxCon` as the number
of connections allowed to establish and gives 0 no meaning, so that would be a
tc8-dut-only convention a real ECU does not share, the opposite of this seam's
goal. The uncollected Event is the honest residue of the standard primitive,
and a real ECU behaves the same way. The opcode backend's passive open is a
single socket and has no child to leave.
