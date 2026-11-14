- **INV-AUDITVERIFY-seals-parse-linkage** `ParseSeals` (`seal.go`) accepts a record set only
  when it is a well-linked chain. Decoding the `audit_seals` value (accepted audit losses)
  through per-line base64 + JSON, a set `ParseSeals` returns has `Seq` 1-based and consecutive
  (`recs[i].Seq == i+1`), an empty `Prev` on the first record, and every later record's `Prev`
  equal to the previous record's `Digest()`; any other shape is rejected with
  `errSealMalformed`, never a panic. This is the only structural gate before the records drive
  gap/truncation coverage (`sealsCover`, `checkSealEvents`); a mis-linked set reading as valid
  would let one acceptance's digest chain to another's. MACs are NOT checked here — `loadSeals`
  authenticates the records under the checkpoint key. Why: the seal record is read from a DB
  text column and is the basis for stepping over an accepted audit-chain gap. Guard:
  `FuzzParseSeals` (auditverify, I7 small-parser sweep).
