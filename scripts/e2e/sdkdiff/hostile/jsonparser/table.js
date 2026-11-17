'use strict';
// JSONTestSuite table for the Node decoder as the Keyorix Node SDK calls it: JSON.parse(Buffer.concat(chunks).toString()).
const fs = require('node:fs');
const path = require('node:path');
const dir = process.argv[2];
for (const n of fs.readdirSync(dir).filter((x) => x.endsWith('.json')).sort()) {
  const s = fs.readFileSync(path.join(dir, n)).toString();
  let r;
  try { JSON.parse(s); r = 'accept'; } catch (e) { r = e instanceof SyntaxError ? 'reject' : 'crash:' + e.constructor.name; }
  process.stdout.write(n + '\t' + r + '\n');
}
