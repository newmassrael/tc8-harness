export type Status = 'active' | 'deprecated';

export interface Verdict {
  state: string;
  verdict: string;
}

export interface TraitInfo {
  description: string;
  approach: string;
  verdicts: Verdict[];
  bpf_group: string;
}

export interface Sources {
  trait_h: string | null;
  scxml: string | null;
  test_dir: string | null;
}

export type PacketDirection = 'tester_to_dut' | 'dut_to_tester' | 'other';

export interface PacketRecord {
  idx: number;
  ts_us: number;
  ts_delta_us: number;
  direction: PacketDirection;
  src_mac?: string;
  dst_mac?: string;
  src_ip?: string;
  dst_ip?: string;
  protocol: string;
  summary: string;
  fields?: Record<string, unknown>;
}

export interface PacketCapture {
  case_id: string;
  outcome: 'pass' | 'fail' | string;
  captured_at?: string;
  tester_mac?: string;
  tester_ip?: string;
  dut_mac?: string;
  dut_ip?: string;
  /**
   * Fetchable location of the capture these records were decoded from,
   * rendered as a download link in the timeline header. Any URL the browser
   * can resolve — same-origin relative path or absolute. Absent ⇒ no link.
   */
  pcap_url?: string;
  /**
   * URI template for opening one packet in a local analyzer. Placeholders:
   *   {idx}   0-based, equals PacketRecord.idx (the '#' column)
   *   {frame} 1-based frame number in pcap_url, i.e. idx + 1
   * Example: "tc8pcap://open?cid=SOMEIPSRV_RPC_01&idx={idx}"
   *
   * The two differ by exactly one because ``idx`` IS the frame's position in
   * the capture: ``tc8-harness decode-pcap`` filters nothing and appends one
   * record per dispatched frame, in file order. A consumer may rely on the
   * offset to build a frame-accurate link.
   *
   * ``packets`` is not necessarily dense, and does not have to be for the
   * offset to hold: ``site/scripts/trim_pcap.py`` elides the middle of an
   * oversize capture, keeping each surviving record's original ``idx`` (never
   * renumbering) and splicing in one synthetic ``[truncated]`` row. That row
   * stands for the elided span rather than a frame, and the timeline leaves it
   * unlinked. Absent ⇒ the '#' cells stay plain text.
   */
  open_uri_template?: string;
  packets: PacketRecord[];
}

export type MessageRole = 'stimulus' | 'expected' | 'fail-trigger' | 'note' | 'case-note';

export interface MessageHighlight {
  /** Packet selector. ``idx`` is 0-based and matches PacketRecord.idx. */
  idx: number;
  /** Short label shown next to the packet row. */
  label: string;
  /** Visual classification — drives row tinting in the timeline. */
  role: MessageRole;
}

export interface ScxmlInfo {
  content: string;
}

export interface CaseRecord {
  case_id: string;
  case_id_raw: string;
  category: string;
  protocol: string;
  section: string;
  spec_order: number;
  status: Status;
  expected: boolean;
  defer_reason: string;
  trait?: TraitInfo;
  sources?: Sources;
  runs?: unknown;
  pcap?: PacketCapture;
  scxml?: ScxmlInfo;
}

export interface IndexEntry {
  case_id: string;
  category: string;
  protocol: string;
  section: string;
  status: Status;
  expected: boolean;
  title: string;
}

export interface IndexFile {
  schema_version: number;
  case_count: number;
  cases: IndexEntry[];
}

export type Locale = 'en' | 'ko';
