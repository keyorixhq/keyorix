'use strict';
// Driver for the Keyorix Node SDK. One protocol line in, one JSON line out (see ../../PROTOCOL.md).
const http = require('node:http');
const path = require('node:path');
const readline = require('node:readline');
const util = require('node:util');
const { AsyncLocalStorage } = require('node:async_hooks');

const plant = process.env.SDKDIFF_PLANT || '';
if (plant === 'P2' || plant === 'P5') {
  const orig = http.request;
  http.request = function patched(options, cb) {
    options = { ...options };
    if (plant === 'P2' && options.path) options.path = options.path.replace('?include_value=true', '');
    if (plant === 'P5' && options.headers && options.headers.Authorization) {
      options.headers = { ...options.headers, Authorization: options.headers.Authorization.replace(/^Bearer /, 'bearer ') };
    }
    return orig.call(http, options, cb);
  };
}
const sdk = require(path.join(process.env.SDKDIFF_SDKS_DIR, 'node', 'keyorix.js'));

const CLIENT_METHODS = ['health', 'listSecretsScoped', 'getSecretScoped', 'getSecretIn', 'getSecretByRef',
  'listDeletedSecrets', 'listProjects', 'createProject', 'listEnvironments'];

// SDK functions this driver calls that the SDK does not define. A renamed method must read as a harness
// failure (driver_error), not as an SDK error to compare, so this is checked up front rather than by
// mapping TypeError at call time (an SDK may throw it on a scenario that is behaviour).
function missingApi() {
  const miss = typeof sdk.login === 'function' ? [] : ['login'];
  if (typeof sdk.Client !== 'function') return miss.concat('Client');
  return miss.concat(CLIENT_METHODS.filter((m) => typeof sdk.Client.prototype[m] !== 'function').map((m) => 'Client.' + m));
}
const MISSING = missingApi();

function field(f) {
  if (f === '~') return null;
  return Buffer.from(f, 'hex').toString('utf8');
}

function classify(err, force) {
  let cls = 'other';
  let status = null;
  if (force) cls = force;
  else if (err instanceof sdk.AuthError) { cls = 'auth'; status = err.statusCode ?? null; }
  else if (err instanceof sdk.SecretNotFoundError) cls = 'not_found';
  else if (err instanceof sdk.KeyorixError) {
    if (err.statusCode !== undefined && err.statusCode !== null) { cls = 'http'; status = err.statusCode; }
    else if (/^(Request failed|Server unreachable)/.test(err.message)) cls = 'network';
  } else if (err instanceof SyntaxError) cls = 'decode';
  let full = '';
  try { full = util.inspect(err, { depth: 4 }).slice(0, 20000); } catch (e2) { full = 'inspect failed'; }
  return { ok: false, class: cls, status, native: (err && err.constructor && err.constructor.name) || typeof err, msg: String(err && err.message !== undefined ? err.message : err).slice(0, 20000), sdk_error: err instanceof sdk.KeyorixError, full };
}

async function run(f) {
  if (MISSING.length > 0) return { driver_error: 'SDK lacks ' + MISSING.join(', ') };
  const cmd = f[0];
  const base = field(f[1]) ?? '';
  const token = field(f[2]) ?? '';
  const timeoutMs = parseInt(f[3], 10) || 0;
  const args = f.slice(4).map(field);
  const copts = timeoutMs > 0 ? { timeout: timeoutMs } : {};
  if (cmd === 'construct') {
    try { new sdk.Client(base, 'x'); return { ok: true, value: { accepted: true } }; } catch (e) { return classify(e, 'validation'); }
  }
  if (cmd === 'login') {
    try {
      const tok = await sdk.login(base, args[0], args[1], timeoutMs > 0 ? timeoutMs : undefined);
      return { ok: true, value: { token_len: tok.length } };
    } catch (e) { return classify(e); }
  }
  let c;
  try { c = new sdk.Client(base, token, copts); } catch (e) { return classify(e, 'validation'); }
  try {
    switch (cmd) {
      case 'health': return { ok: true, value: await c.health() };
      case 'list_secrets': return { ok: true, value: secretList(await c.listSecretsScoped('alpha', args[0])) };
      case 'get_secret': return { ok: true, value: await c.getSecretScoped(args[0], 'alpha', args[1]) };
      case 'get_secret_in': return { ok: true, value: await c.getSecretIn(args[0], args[1], args[2]) };
      case 'get_secret_by_ref': return { ok: true, value: await c.getSecretByRef(args[0]) };
      case 'list_deleted_secrets': {
        if (typeof args[0] !== 'string' || !/^[0-9]{1,9}$/.test(args[0])) return { na: true };
        return { ok: true, value: secretList(await c.listDeletedSecrets(Number(args[0]))) };
      }
      case 'list_projects': {
        const p = await c.listProjects();
        return { ok: true, value: p.map((x) => ({ id: x.id, name: x.name, description: x.description, created_at: x.createdAt })) };
      }
      case 'create_project': {
        const x = await c.createProject(args[0], args[1]);
        return { ok: true, value: { id: x.id, name: x.name, description: x.description, created_at: x.createdAt } };
      }
      case 'list_environments': {
        const e = await c.listEnvironments(Number(args[0]));
        return { ok: true, value: e.map((x) => ({ id: x.id, project_id: x.projectId, name: x.name })) };
      }
      default: return { driver_error: 'unknown cmd ' + cmd };
    }
  } catch (e) { return classify(e); }
}

// Hostile mode only (SDKDIFF_HOSTILE=1, set by `sdkdiff hostile`): unhandled rejections and uncaught exceptions are
// reported, not fatal, so that the harness can see them (oracle O1). Differential runs keep Node's default behaviour.
// Each call runs in its own AsyncLocalStorage context, and an event is attributed to the call whose async work raised
// it (Node runs both handlers in the context of the failing promise or callback), not to whichever call is running
// when it fires.
const hostile = process.env.SDKDIFF_HOSTILE === '1';
const callCtx = new AsyncLocalStorage();
const unattributed = []; // events of already answered calls or outside any call: reported on the next line as late_side_events
function side(kind, e) {
  const ev = kind + ': ' + String(e && e.stack || e).slice(0, 2000);
  const c = callCtx.getStore();
  if (c && !c.answered) {
    c.events.push(ev);
    if (c.wake) c.wake();
  } else {
    unattributed.push((c ? 'call ' + c.seq + ' (answered): ' : 'no call: ') + ev);
  }
}
if (hostile) {
  process.on('unhandledRejection', (e) => side('unhandledRejection', e));
  process.on('uncaughtException', (e) => side('uncaughtException', e));
}

// runHostile runs one call. After a side event the call gets until its own timeout plus 1 s to settle, so its real
// result is kept; if it does not settle, the answer is the side event and is marked abandoned, and the harness then
// restarts the driver so the still-running SDK work cannot reach the next call.
async function runHostile(seq, fields) {
  const c = { seq, events: [], wake: null, answered: false };
  const done = callCtx.run(c, () => run(fields)).catch((e) => ({ driver_error: String(e && e.stack || e) }));
  const woken = new Promise((resolve) => { c.wake = () => resolve(null); });
  let res = await Promise.race([done, woken]);
  let abandoned = false;
  if (res === null) {
    const graceMs = (parseInt(fields[3], 10) || 5000) + 1000;
    let timer;
    const grace = new Promise((resolve) => { timer = setTimeout(() => resolve(null), graceMs); });
    res = await Promise.race([done, grace]);
    clearTimeout(timer);
    if (res === null) {
      abandoned = true;
      res = { ok: false, class: 'other', native: 'SideEvent', sdk_error: false, msg: 'side event during call, call did not settle', full: '' };
    }
  }
  // one turn of the event loop, so a rejection left unhandled by the call itself is still reported with it
  await new Promise((resolve) => setImmediate(resolve));
  c.answered = true;
  c.wake = null;
  if (c.events.length) res.side_events = c.events.splice(0);
  if (abandoned) res.abandoned = true;
  return res;
}

(async () => {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  let seq = 0;
  for await (const line of rl) {
    if (!line) continue;
    const t0 = Date.now();
    let res;
    if (hostile) {
      res = await runHostile(++seq, line.split('\t'));
      if (unattributed.length) res.late_side_events = unattributed.splice(0);
    } else {
      try { res = await run(line.split('\t')); } catch (e) { res = { driver_error: String(e && e.stack || e) }; }
    }
    res.ms = Date.now() - t0;
    process.stdout.write(JSON.stringify(res, (k, v) => (v === undefined ? null : v)) + '\n');
  }
})();

function secretList(s) {
  return s.map((x) => ({ id: x.id, name: x.name, type: x.type, project_id: x.projectId, environment: x.environment, created_at: x.createdAt, purge_at: x.purgeAt ?? "" }));
}
