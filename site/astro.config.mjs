// @ts-check
import { defineConfig } from 'astro/config';

// GH Pages base path. Override with SITE_BASE env var when deploying under
// a subpath (e.g. /tc8-harness/). Local dev defaults to '/'.
const base = process.env.SITE_BASE ?? '/';
const site = process.env.SITE_URL ?? 'http://localhost:4321';

export default defineConfig({
  site,
  base,
  trailingSlash: 'always',
  i18n: {
    defaultLocale: 'en',
    locales: ['en', 'ko'],
    routing: {
      prefixDefaultLocale: true,
    },
  },
  build: {
    format: 'directory',
  },
});
