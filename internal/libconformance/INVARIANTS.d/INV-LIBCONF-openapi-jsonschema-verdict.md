- **INV-LIBCONF-openapi-jsonschema-verdict** For a JSON Schema restricted to the
  common keyword subset (type/properties/required/enum/min*/max*/pattern/items/
  additionalProperties) and any instance both getkin/kin-openapi and
  santhosh-tekuri/jsonschema/v6 can process, the two validators must return the SAME
  accept/reject verdict, except for documented OpenAPI-3.0-vs-JSON-Schema-2020-12 dialect
  splits that are on the allowlist with a reason (see `openapiDiffAllow`: `nullable` extension,
  empty `enum`, float64 number coercion, OpenAPI null semantics, and the upstream
  jsonschema/v6 bignum panic), each keyed only when its own mechanism and verdict
  direction hold. A verdict split outside those classes
  means one validator would admit an instance the other rejects. Why: DF1. Guard:
  `FuzzOpenAPIVsJSONSchema` + `TestOpenAPICompare_RedGreen` +
  `TestOpenAPIDiffAllowlistNoDead` (`internal/libconformance`).
