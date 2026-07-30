/**
 * Capture-link policy for the packet timeline.
 *
 * A ``PacketCapture`` may carry two optional fields — ``pcap_url`` (where the
 * capture can be fetched) and ``open_uri_template`` (how one packet is handed
 * to a local analyzer). Both are authored by whoever writes
 * ``pcap/<CASE_ID>.json``: the public site build, or an out-of-repo overlay
 * root (``SITE_EXTRA_CASE_ROOTS``). Because that value ends up in an ``href``
 * on a publicly deployed page, the scheme is filtered here rather than in
 * markup — this module owns the policy, the component only renders what it
 * hands back.
 */

/** Schemes that execute rather than locate. Never emitted into an ``href``. */
const EXECUTABLE_SCHEMES = ['javascript:', 'vbscript:', 'data:'];

/**
 * Return ``uri`` when it is safe to place in an ``href``, else ``null``.
 *
 * Deliberately a denylist: the useful set is open-ended (a relative URL,
 * ``http(s):``, or any locally registered custom scheme such as ``tc8pcap:``),
 * while the executable set is small and closed — an allowlist would have to
 * enumerate every analyzer scheme an integrator might register. Whitespace and
 * C0 controls are stripped before the comparison because a browser strips them
 * before parsing the scheme, so ``java\nscript:`` is the same threat.
 */
export function captureHref(uri: string | undefined): string | null {
  if (!uri) return null;
  const probe = uri.replace(/[\u0000-\u0020]/g, '').toLowerCase();
  if (EXECUTABLE_SCHEMES.some((scheme) => probe.startsWith(scheme))) {
    console.warn(`[pcap] refusing executable URI scheme, link dropped: ${uri}`);
    return null;
  }
  return uri;
}

/**
 * ``protocol`` value of the synthetic row ``site/scripts/trim_pcap.py`` splices
 * in when a capture's JSON is too large for the pcap-data branch: it stands for
 * the elided span, not for one frame. Its ``idx`` is a real frame number (the
 * first elided one), which is exactly why it must not be offered as a link —
 * a reader would take the row to BE that frame. The string is the contract
 * between the trimmer and this component; changing it needs both sides.
 */
const TRUNCATION_MARKER_PROTOCOL = '[truncated]';

/** True when this record summarizes elided frames instead of naming one. */
export function isTruncationMarker(protocol: string): boolean {
  return protocol === TRUNCATION_MARKER_PROTOCOL;
}

/**
 * Expand an ``open_uri_template`` for one packet: ``{idx}`` → the 0-based
 * record index, ``{frame}`` → the 1-based frame number (``idx + 1``).
 *
 * Both substitutions are integers, so the template only has to clear
 * ``captureHref`` once — per-row expansion cannot introduce a new scheme.
 */
export function expandOpenUri(template: string, idx: number): string {
  return template
    .replace(/\{idx\}/g, String(idx))
    .replace(/\{frame\}/g, String(frameNumber(idx)));
}

/**
 * The frame number a record names, as every capture tool counts them: 1-based.
 *
 * The single home of the 0-to-1 offset. The link target and the label that tells
 * the reader which frame they are about to open must never disagree, and they
 * cannot while both derive the number here.
 */
export function frameNumber(idx: number): number {
  return idx + 1;
}
