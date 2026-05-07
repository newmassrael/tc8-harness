/**
 * Section registry for the case-detail page.
 *
 * Each section is rendered in order if its ``requires(case)`` predicate is
 * true. Adding a new section: populate a top-level field in the case JSON,
 * write a component that takes ``{ case, locale }``, and add an entry here.
 */

import HeaderSection from '~/components/sections/HeaderSection.astro';
import ApproachSection from '~/components/sections/ApproachSection.astro';
import VerdictsSection from '~/components/sections/VerdictsSection.astro';
import PacketTimeline from '~/components/sections/PacketTimeline.astro';
import ScxmlSection from '~/components/sections/ScxmlSection.astro';
import SourcesSection from '~/components/sections/SourcesSection.astro';
import RelatedSection from '~/components/sections/RelatedSection.astro';
import { sisterCases } from './cases';
import type { CaseRecord } from './types';

export interface SectionDef {
  id: string;
  Component: typeof HeaderSection;
  requires: (c: CaseRecord) => boolean;
}

export const sections: SectionDef[] = [
  { id: 'header',   Component: HeaderSection,   requires: () => true },
  { id: 'approach', Component: ApproachSection, requires: (c) => !!c.trait?.approach || c.status === 'deprecated' },
  { id: 'verdicts', Component: VerdictsSection, requires: (c) => (c.trait?.verdicts?.length ?? 0) > 0 },
  { id: 'pcap',     Component: PacketTimeline,  requires: (c) => (c.pcap?.packets?.length ?? 0) > 0 },
  { id: 'scxml',    Component: ScxmlSection,    requires: (c) => !!c.scxml?.content },
  { id: 'sources',  Component: SourcesSection,  requires: (c) => !!c.sources },
  { id: 'related',  Component: RelatedSection,  requires: (c) => sisterCases(c).length > 0 },
  // Reserved:
  //   { id: 'runs',    Component: RunHistory,    requires: (c) => !!c.runs },
  //   { id: 'diagram', Component: ScxmlDiagram,  requires: (c) => !!c.scxml?.diagram },
];
