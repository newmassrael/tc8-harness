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

## What an answer means, and who records it

A DUT-control call has three outcomes, and a `bool` cannot tell two of them
apart: the DUT did it, the DUT refused (and why), or no answer came. CLOSE and
ABORT return a `DutCallOutcome` with all three, the refusal reason in
backend-neutral terms (`kConnectionDoesNotExist` for PRS_TPSP E_TCP_CNE or
E_ISD, and for the opcode UT's unknown-socket status), because RFC 793 3.9
makes "CLOSE on a connection that does not exist is refused" a requirement a
case can grade. `createTcp` (testability CREATE_AND_BIND alone, gated by
`kCapTcpCreateClosed`) gives such a case a connection in CLOSED to ask about.
RECEIVE (normal and urgent) returns a `DutReceiveOutcome`: the bytes the DUT's
application got, a refusal, or no answer. A case grading delivery fails a wrong
answer or a refusal and stays inconclusive on no answer, because only an answer
says something about the DUT.

The UDP receive question has the same arm-then-trigger shape (`receiveUdp`). A
case gives it the probe and a sentinel, both as callbacks; the answer comes back
in-process and the stimulus records it in `Captured` (`udp_receive_answer.h`).
The opcode backend runs the probe and asks the DUT, whose `received=0` is an
affirmative answer. The testability backend binds the port, arms
RECEIVE_AND_FORWARD before the probe, and sends a well-formed sentinel datagram
after it. "Sentinel forwarded, probe not" is an observed discard; "neither
forwarded" is a silence, which is no answer and leaves the case inconclusive. The
premise is that a socket's receive queue keeps arrival order. The socket is bound
on any address so the sentinel, sent to the DUT's unicast address, proves the path
even when the probe went to an address the DUT is expected to refuse. A case's
machine reacts to the runner's stimulus-settled hook (`onStimulusSettled`), not to
a wire frame, so no control-channel frame is evidence for this family.

Every backend is handed out inside a `RecordingDutControl`
(`recording_dut_control.h`, applied by `makeDutControl`), which turns an action
the case needed and did not get into an unperformed stimulus, so a case that
ignores a result cannot grade the tester's failure as the DUT's silence
(docs/verdict_policy.md Section 2.1, hypothesis S). What counts depends on why
the call was made, which the case states with a `DutCallIntentScope`
(`dut_call_intent.h`): a stimulus by default (anything short of done is
recorded), a graded call (only no answer is recorded; a refusal is the DUT's
answer), or cleanup after the graded part (nothing is recorded). A receive is
a query: whatever the DUT answered is an observation, so only no answer is
recorded, outside cleanup. Accept and the state probe are observations and
record nothing.

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
