import type { Locale } from './types';

const BASE = (import.meta.env.BASE_URL ?? '/').replace(/\/$/, '');
const REPO = process.env.REPO_URL ?? 'https://github.com/newmassrael/tc8-harness';
const REF = process.env.REPO_REF ?? 'main';

export function localePath(locale: Locale, ...parts: string[]): string {
  const tail = parts.filter(Boolean).join('/');
  const slash = tail ? '/' : '';
  return `${BASE}/${locale}/${tail}${slash}`;
}

export function casePath(locale: Locale, caseId: string): string {
  return localePath(locale, 'cases', caseId.toUpperCase());
}

export function indexPath(locale: Locale): string {
  return localePath(locale);
}

export function repoBlob(path: string): string {
  return `${REPO}/blob/${REF}/${path}`;
}
