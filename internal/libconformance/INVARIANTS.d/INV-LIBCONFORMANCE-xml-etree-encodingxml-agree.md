- **INV-LIBCONFORMANCE-xml-etree-encodingxml-agree** For any input both beevik/etree and
  encoding/xml accept, their namespace-resolved canonical trees (element {namespace-URI,
  local-name}, attributes, text, child order) must be identical, except for the single
  documented difference that an UNDECLARED namespace prefix resolves differently (etree →
  "", encoding/xml keeps the literal prefix) — a namespace-ill-formed document a SAML/
  XML-DSig consumer rejects upstream. A DECLARED-namespace, local-name, text, or
  structural disagreement is the raw material of a signature-wrapping identity split
  (internal/saml/provider.go reads the same response bytes via a strict encoding/xml walk
  AND crewjam/etree). Why: DF1, SAML XSW class. Guard:
  `FuzzXMLEtreeVsEncodingXML` + `TestXMLCompare_RedGreen` + `TestXMLDiffAllowlistNoDead`
  (`internal/libconformance`).
