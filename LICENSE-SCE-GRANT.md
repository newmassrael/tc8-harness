# SCE Platform Grant for tc8-harness

**Version 1.0** - issued by the copyright holder of the SCXML Core Engine
("SCE"), newmassrael.

This file is a separate grant. It is not part of the Apache License 2.0
that covers the tc8-harness source (see [LICENSE](LICENSE)), and it does not
change that license. It states what the SCE copyright holder additionally
permits for SCE as used through tc8-harness.

## 1. Why this exists

tc8-harness builds its conformance cases from SCXML with the SCE code
generator and runs them on the SCE runtime. Projects built on tc8-harness
author their own cases the same way. SCE's Linking Exception excludes a
"Competing Product" from its permissions, and a tool that lets others build
software on it can be read as one. This grant removes that doubt for
tc8-harness and for the projects built on it, within the limits below.

## 2. Definitions

Terms in capitals that are not defined here have the meaning given in the SCE
Linking Exception ([third_party/sce/LICENSE-EXCEPTION.md](third_party/sce/LICENSE-EXCEPTION.md)
for the vendored release, or the Exception that ships with the SCE release
in use).

- **"Platform"**: tc8-harness as published in its repository
  (https://github.com/newmassrael/tc8-harness), with the unmodified SCE
  release it vendors under `third_party/sce/`.
- **"Platform Interfaces"**: the ways the Platform offers for building and
  running conformance cases: its command line, its installed SDK headers and
  CMake package, its CMake functions, and the case-generation step its
  build runs on SCXML documents.
- **"Downstream Project"**: software that is built on the Platform and uses
  SCE only through the Platform Interfaces, to author, build, run or report
  on conformance cases.

## 3. What is granted

The SCE copyright holder grants, to the Platform and to every Downstream
Project, free of charge and for as long as section 5 holds:

1. **The Platform is not a Competing Product.** For the purposes of the
   Linking Exception, the Platform's use of SCE, and its offering of the
   Platform Interfaces to Downstream Projects, is not the provision of
   state-machine execution, SCXML processing, code generation or authoring
   to third parties.
2. **Use through the Platform Interfaces.** A Downstream Project may use the
   SCE runtime, `sce-codegen`, and the Generated Output they produce, as the
   Platform Interfaces invoke them, under terms of its own choice for the
   Downstream Project, on the same conditions as Linking Exception sections
   2 and 3 except that a Downstream Project is not a Competing Product by
   reason of building on the Platform.
3. **Closed source is permitted.** A Downstream Project need not publish its
   own source, its SCXML documents or its Generated Output, and users who
   interact with it over a network acquire no right to them through
   AGPL-3.0 section 13 by reason of SCE.

## 4. What is not granted

- **Use outside the Platform Interfaces.** Taking SCE out of the Platform to
  run, generate or author state machines for other purposes, or offering
  SCE's functions to others other than through the Platform, is not covered.
  The SCE license that ships with the release governs that use.
- **A modified SCE.** The Library or a Tool modified by anyone, and the
  Generated Output of a modified Tool or templates, is governed by AGPL-3.0
  in full unless the SCE Commercial License is held. Selecting a documented
  build option, feature flag or configuration value is not a modification.
- **A separate Competing Product.** A Downstream Project that is also a
  Competing Product for a reason other than building on the Platform is not
  helped by this grant.
- **Anything else in the Platform.** Third-party components under
  `third_party/` keep their own licenses.

## 5. Conditions and ending

1. Keep SCE's copyright notices, the Linking Exception, and a reference to
   AGPL-3.0 and to this file in the Downstream Project's documentation or
   "About" screen, and keep the license headers of Generated Output.
2. This grant ends for a copy of the Platform when that copy modifies SCE or
   when the Platform itself becomes a Competing Product by a reason other
   than the one section 3 removes. It ends for a Downstream Project only
   when that project breaks section 4.
3. Ending is not retroactive. A copy already conveyed while the grant held
   keeps the terms it was conveyed under.

## 6. Relationship to the SCE licenses

- For SCE releases licensed under AGPL-3.0 with the Linking Exception, this
  is an additional permission under section 7 of AGPL-3.0, given by the
  copyright holder.
- For SCE releases licensed under LGPL-2.1 with the Static Linking
  Exception (the release vendored at the time of writing), it supplements
  that Exception.
- It adds to the permissions SCE already gives and removes none of them. If
  a Downstream Project qualifies under the SCE license alone, it may rely
  on that instead.
- It does not replace the SCE Commercial License for uses outside
  section 3.

## 7. No warranty

This grant is provided as is. Nothing in it is a warranty of SCE or of the
Platform, and nothing in it is legal advice to a Downstream Project.

## Contact

- **Email:** newmassrael@gmail.com
- **GitHub:** https://github.com/newmassrael/tc8-harness
