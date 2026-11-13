- **INV-GRAMMAR-decode-total-and-clean-output-wellformed** `DecodeDER`, `DecodeXML`
  and `DecodeSAMLFragment` are total and bounded for ANY input (including empty and
  truncated): they never panic, and the tree they build is capped by the
  `maxRecurseDepth`/`maxChildren`/`maxNodes`/`maxContentLen`/`maxChainDepth`/`maxSiblings`
  constants so the builder itself cannot OOM or hang before the target's parser even
  runs. Separately, output built with the ZERO mutation set must be well-formed by
  construction: a zero-mutation DER tree re-parses through `encoding/asn1` and a
  zero-mutation XML document parses through `beevik/etree` — otherwise a fuzz target
  that fed "clean" grammar output could never reach the parser it means to exercise,
  and a green run would prove nothing. Mutation flags (`DERMut`/`XMLMut`) are the ONLY
  thing allowed to produce parser-rejected bytes, and each one must actually perturb
  the encoding (an inert mutation gives the engine a dead choice). Why: the grammar
  campaign's own soundness — a generator that crashes or emits malformed "clean" bytes
  is the counterpart to "a guard nobody has watched fail is not a guard"
  (`/mnt/data/wave4/out/wg-REPORT.md`). Guard: `TestDecodeDERTotal`,
  `TestDecodeXMLTotalAndWellFormed`, `TestDecodeSAMLFragmentTotal`,
  `TestDERZeroMutationRoundTrips`, `TestDERDeepChain`, `TestXMLDeepChain`,
  `TestDERMutationsChangeBytes` (`internal/fuzzutil/grammar/grammar_test.go`).
