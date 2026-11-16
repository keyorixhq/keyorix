- **INV-FUZZDIFF-undocumented-difference-fails** `Comparator.Compare` reports a divergence
  whenever the implementations' verdicts disagree AND no `DocumentedDiff.Explains` row
  accounts for that exact set of verdicts. A difference is suppressed only by a row that
  cites, in prose, why it is acceptable and which side is right per the spec; the table is
  empty by default, so an undocumented difference always fails. Why: a differential oracle
  whose default is "tolerate" silently swallows real leads. Guard:
  `TestCompare` (the "different impls diverge" red row, the "documented difference suppresses"
  row, and the "accept/accept but subject disagrees" row).
<!-- section: Oracle -->
