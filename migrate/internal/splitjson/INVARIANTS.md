# splitjson invariants

`splitjson.Object` explodes a cloud provider's raw secret VALUE (AWS/Azure/GCP
`--split-json`) into one Keyorix secret per top-level JSON key — attacker-controlled
input at first contact. The rules a change here must keep are below; each links to the
fuzz target or test that enforces it.

New invariants go in `INVARIANTS.d/INV-SPLITJSON-<kebab-slug>.md` (one per file), not
appended here.

Format: `INV-SPLITJSON-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.
