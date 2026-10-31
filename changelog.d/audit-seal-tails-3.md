### Security
- **`admin audit accept-loss` no longer seals rewritten rows as a loss (#3802).** The audit entry hash is unkeyed, so a database writer could rewrite rows before the gap, recompute their hashes and delete the next row. The break then looked like a genuine deletion, and the seal certified the forged rows. The command now refuses:
  - a break with no id missing;
  - a signed certification taken after the rows before the gap that still counts every surviving row;
  - any row whose hash differs from what a signed checkpoint (every checkpoint, not only the latest), the high-water mark, the retention anchor, the signed verification state, the host witness, an earlier seal or `--anchor` certified.

  Surviving rows before a gap that nothing signed pins are listed in the plan as unauthenticated and recorded in the seal (`unpinned`).
