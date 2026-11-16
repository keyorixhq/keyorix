# Expected-difference table — XML parser-differential oracle (X1)

Oracle X1 (`FuzzXMLParserDifferential`, `xml_parser_differential_fuzz_test.go`) asserts:

> for any input the `mattermost/xml-roundtrip-validator` (xrv) **accepts**, the resolved
> element *skeleton* — ordered `{namespace-uri}local` element names + nesting depth, and each
> element's set of resolved attribute names — built by **beevik/etree** (the signature-layer
> parser crewjam/saml drives into goxmldsig) must equal the one built by an independent
> **encoding/xml** `Decoder.Token()` walk (the layer crewjam's `unmarshalElement` relies on).

A document xrv accepts whose two skeletons disagree is a **validator-bypass candidate**. This
table names every divergence class that is KNOWN and benign, so that only a NEW class reaches
the failing assertion. The first three classes (N1–N3) are enforced in code by
`normalizeSkeleton`/`normalizeName`/`normalizeAttrs` — that function IS the machine-checked
form of this table; keep them in lockstep. N4 and the two scope notes are enforced by how the
skeletons are built. **This table is a talk slide: every row is a way two conformant Go XML
libraries read the same bytes differently, and a reason it is not (here) a signature bypass.**

| id | class | etree sees | encoding/xml (Token) sees | why it is NOT a bypass here | enforced by |
|----|-------|-----------|---------------------------|-----------------------------|-------------|
| N1 | Undeclared namespace prefix (`<a:x/>` with no `xmlns:a`) | element `x` in **no** namespace (prefix dropped) | element `x` in pseudo-namespace `{a}` (prefix kept verbatim) | An undeclared prefix is not namespace-well-formed. It can never ride inside a *signed* element: goxmldsig's exclusive-C14N (`etreeutils` NS resolution) errors on an unresolvable prefix before any digest is computed. Neither layer grants the element a *real* namespace URI, so this is representation of malformed input, not a signature-vs-application identity swap. | `normalizeName` (drops `{pfx}` wrappers whose contents are not a real URI) |
| N2 | Reserved `xml:` prefix (`xml:lang`, `xml:space`) | attribute in **no** namespace (etree does not auto-bind `xml:`) | attribute in `{http://www.w3.org/XML/1998/namespace}` (always-bound reserved URI) | Both layers agree the attribute exists and on its local name; they differ only on attaching the reserved, universally-bound URI. No element identity or signed-subtree membership turns on it. | `normalizeName` (drops the reserved-`xml:` URI wrapper) |
| N3 | Duplicate attribute name (`<a b="1" b="2"/>`) | keeps **one** `b` | keeps **both** `b`s (Strict=false) | A repeated attribute name is not well-formed XML; both layers *see* the malformedness, they just render the count differently. The skeleton compares the *set* of attribute names, so the count difference is removed; attribute *values* are out of scope (see below). | `normalizeAttrs` (de-duplicates names) |
| N4 | etree stricter than xrv+encoding/xml on malformed syntax (e.g. `<r A0000>` — a bare word where an attribute is expected) | parse **error** (no tree) | lenient parse into a tree; xrv accepts (token round-trips) | This is etree being **stricter** than the round-trip check. etree is crewjam's *first* gate (`ParseResponse` decodes with etree before any unmarshal), so "the signature layer rejects what the round-trip check accepts" is the SAFE direction — crewjam rejects the document outright. Only the opposite direction (etree builds a tree encoding/xml cannot) is reported as a finding. | the one-sided-parse branch only fires for `etree-nonempty ∧ xml-empty` |

## Scope notes (what the skeleton deliberately does not compare — also "not verified")

- **S1 Trailing content after the first root** (`<a><b/></a><c/>`): xrv accepts multiple
  top-level roots; etree's `Root()` exposes only the first, and so does crewjam's single-
  element `unmarshalElement`. The encoding/xml walk is therefore stopped at the end of the
  first root subtree (`xmlSkeleton`), matching etree. Trailing/epilogue content is a separate
  class covered at the SAML layer by `internal/saml`'s `provider_epilogue` tests, not here.
- **S2 Text, CDATA, comments, PIs, attribute VALUES, attribute ORDER** are not part of the
  skeleton. Text/CDATA/comment splicing inside a value (e.g. a comment inside a `NameID`) is
  the SAML-layer provenance concern and is covered by oracles S1/S2 on branch
  `fuzz/saml-differential`. At the pure-parser layer these are representational noise.
- **S3 One fixed encoding/xml configuration** (`Strict=false`, identity charset). A different
  configuration (e.g. crewjam's `Strict`-default `xml.Unmarshal`) is a distinct oracle.
- **S4 Entities / DOCTYPE / external references** are never expanded by Go's `encoding/xml`
  (or etree, which is built on it), so that class is closed by construction, not asserted.

## How this list was established to be complete *as of the seeds run*

The classes above are every divergence observed between etree and encoding/xml on inputs xrv
accepts, across the manual probe corpus (see the report's "Probe" section) plus ~90 s / ~850k
execs of coverage-guided fuzzing. Completeness is bounded by that run: the oracle's PURPOSE is
to make a NEW class fail loudly, at which point it is triaged and either fixed (if a real
bypass) or added here with its justification. A row here is a claim that a class is benign *for
the crewjam/goxmldsig signature path*; if that path changes, re-audit the row.
