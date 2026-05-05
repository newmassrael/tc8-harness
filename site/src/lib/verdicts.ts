import type { CaseRecord, Locale, Verdict } from './types';
import { t } from './i18n';
import { localizedVerdictMeaning } from './overrides';

const KEEP_UPPER = new Set([
  'dut', 'arp', 'tcp', 'udp', 'icmp', 'ip', 'ipv4', 'ipv6', 'mac',
  'ack', 'syn', 'fin', 'rst', 'msl', 'mss', 'rfc', 'sd', 'gc',
  'mtu', 'lan', 'wnp', 'rto', 'mss', 'oow', 'unacc', 'ets',
]);

function humanizeReason(reason: string): string {
  return reason
    .split(/[_-]/)
    .map((w, i) => {
      const lower = w.toLowerCase();
      if (KEEP_UPPER.has(lower)) return lower.toUpperCase();
      if (i === 0 && w.length) return w[0].toUpperCase() + w.slice(1);
      return w;
    })
    .join(' ');
}

export type Outcome = 'pass' | 'fail' | 'running' | 'unknown';

export interface VerdictView {
  state: string;
  raw: string;
  outcome: Outcome;
  reason: string;
}

export function classifyVerdict(c: CaseRecord, v: Verdict, locale: Locale): VerdictView {
  const raw = v.verdict;
  const override = localizedVerdictMeaning(c, locale, v.state);
  let outcome: Outcome;
  let reason: string;

  if (raw === 'pass') {
    outcome = 'pass';
    reason = t(locale, 'case.verdicts.pass' as any);
  } else if (raw === 'running') {
    outcome = 'running';
    reason = t(locale, 'case.verdicts.running' as any);
  } else {
    const m = /^fail:(.+)$/.exec(raw);
    if (m) {
      outcome = 'fail';
      reason = humanizeReason(m[1]);
    } else {
      outcome = 'unknown';
      reason = humanizeReason(raw);
    }
  }

  return { state: v.state, raw, outcome, reason: override ?? reason };
}
