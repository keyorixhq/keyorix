- **INV-SW-read-only-when-fully-lexed** The tracker's classifier (`classifyStatement`) counts a
  statement as anything but a fenced write only after `lexStatement` has read the whole text as
  PostgreSQL's lexer does: string literals (`''`, E'' backslash escapes), dollar quotes, quoted
  identifiers, `--` comments ended by `\n` or `\r`, nested `/* */`. A `;` inside one of these does not
  make a second statement; a `;` outside them with anything but `;` and white space after it does,
  and so does any text it cannot read with certainty (an unterminated quote or comment, a backslash right
  before a quote in a string without the E prefix, a U& identifier, a `$` that is no parameter, identifier part or
  dollar quote). Verbs and transaction control are read with comments blanked out, so a comment cannot
  hide the verb or turn `ROLLBACK TO` into an end. Why: #3978 (the trigger-integrity tick's
  `concat_ws('; ', ...)` read moved the generation every 30 s); the classifier deciding what counts as
  a write fails stale-cache side when wrong. Guard: `TestClassifyStatement_AdversarialStaysFenced`
  (rows marked pre-#3978 red before the lexer), `TestClassifyStatement_SemicolonInALiteralIsARead`
  (red before the lexer), `TestClassifyStatement_CommentsDoNotChangeTransactionControl`,
  `FuzzClassifyStatement` (a second statement appended after any text read as complete is always a
  fenced write), `TestTracker_TriggerIntegrityTicksAreNotFencedWrites` (Postgres; red before the lexer).
