- **INV-HTTP-scim-active-never-silently-ignored** A SCIM Users request that carries `active`
  (PATCH with path `active`, the path-less PATCH object form, PUT, POST) decodes it through
  one tolerant decoder, `parseSCIMBool` (`scim_bool.go`): a JSON bool or the strings
  `"true"`/`"false"` in any case. Anything else that is present (another string, a number,
  `null`, an object, a replace op with no value) answers `400 invalidValue` and changes
  nothing; it never answers `200`. PATCH op names and attribute names are matched
  case-insensitively; a path that is not `active` stays an ignored no-op. Why: Microsoft
  Entra ID sends `{"op":"Replace","path":"active","value":"False"}`; a strict bool unmarshal
  dropped it, the handler answered 200 and the terminated user stayed active with its PATs
  and sessions live. Guard: `scim_active_bool_test.go` (`TestSCIM_PatchActiveStringDeactivates`
  reads the user row and its PAT rows back from storage; `TestSCIM_PatchActiveGarbageIs400`,
  `TestSCIM_PutActiveString`, `TestSCIM_PostActiveString`, `TestParseSCIMBool`). Not covered:
  SCIM Groups (`scim_groups.go` has no boolean attribute).
