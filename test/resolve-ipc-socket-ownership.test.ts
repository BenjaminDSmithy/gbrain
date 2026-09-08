/**
 * Resolve-IPC socket ownership (#4896 follow-up): a live listener is never
 * displaced by a later `startResolveIpcServer` on the same path — not by a
 * racing starter, not by a prober whose connect the busy owner refused — a
 * dead owner is reaped as soon as it is known dead, and a server's shutdown
 * unlinks only the socket file it created.
 *
 * Background (2026-09-06, Postgres brain, always-on provider): before #4896
 * the start path unlinked the path unconditionally before listen() and every
 * exiting serve unlinked it again: 87 forced re-binds in 8 h, 13 % of hook
 * prompts ipc_unavailable. #4896's probe left three ways to lose the socket,
 * pinned here: two serves probing the same stale file in the same few
 * microseconds (no start lock); a connect refused by a LIVE but stalled owner
 * (Bun 1.3.13 / macOS: 172 of 300 connects during a 4 s stall failed with
 * ENOENT, the dead-file code); and Bun's server.close() unlinking the
 * PATHNAME rather than the listener's own file, so a displaced owner's exit
 * took the newcomer's socket with it. In-process unix-socket servers only.
 */
import { describe, test, expect, afterEach } from 'bun:test';
import {
  mkdtempSync, mkdirSync, rmSync, statSync, existsSync, writeFileSync, unlinkSync, utimesSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  startResolveIpcServer,
  resolveViaIpc,
  IPC_UNAVAILABLE,
} from '../src/core/context/resolve-ipc.ts';
import type { PointerBlock } from '../src/core/context/retrieval-reflex.ts';

// The helpers this change ADDS are loaded lazily so the module still imports
// against the pre-change source: the CONTRIBUTING discrimination check
// (scripts/check-test-discriminates.sh) reverts src/ and re-runs this file,
// and a top-level import of a missing export would crash the whole module
// (the vacuous-failure class it warns about) instead of letting the
// behavioural cases below fail on behaviour.
type ResolveIpcModule = typeof import('../src/core/context/resolve-ipc.ts');
async function newApi(): Promise<ResolveIpcModule> {
  return (await import('../src/core/context/resolve-ipc.ts')) as ResolveIpcModule;
}
const MODULE_PATH = new URL('../src/core/context/resolve-ipc.ts', import.meta.url).pathname;

const servers: Array<{ close: () => void }> = [];
const dirs: string[] = [];
afterEach(() => {
  for (const s of servers.splice(0)) { try { s.close(); } catch { /* noop */ } }
  for (const d of dirs.splice(0)) { try { rmSync(d, { recursive: true, force: true }); } catch { /* noop */ } }
});

function tmpSock(): string {
  const d = mkdtempSync(join(tmpdir(), 'rr-ipc-own-'));
  dirs.push(d);
  return join(d, 'resolve.sock');
}

function blockNamed(tag: string): PointerBlock {
  return { pointers: [], text: `owner:${tag}` };
}

async function startNamed(socketPath: string, tag: string) {
  const server = await startResolveIpcServer(socketPath, async () => blockNamed(tag));
  if (server) servers.push(server);
  return server;
}

/**
 * A child listens on `socketPath` with a bare net.Server (no owner record)
 * and exits without closing: the kernel closes the fd, the socket FILE stays
 * behind — a crashed-owner leftover a pre-record owner would leave.
 */
function leaveBareSocket(socketPath: string): void {
  const child = Bun.spawnSync([process.execPath, '-e',
    'const net=require("node:net");const s=net.createServer();s.listen(process.argv[1],()=>process.exit(0));', socketPath]);
  expect(child.exitCode).toBe(0);
  expect(statSync(socketPath).isSocket()).toBe(true);
}

// A pid no process has: far above any pid_max (macOS 99998, Linux 2^22).
const DEAD_PID = 2_147_483_000;

// Unix-socket files have inodes and can be unlinked under a live owner; Windows
// AF_UNIX entries are invisible to Bun's statSync (#4333), so the inode- and
// mtime-based cases are POSIX-only (the existing suites guard the same way).
const posix = process.platform !== 'win32';

describe('resolve-ipc socket ownership', () => {
  test.skipIf(!posix)('a live listener is not displaced by a second start on the same path', async () => {
    const sock = tmpSock();
    const first = await startNamed(sock, 'first');
    expect(first).not.toBeNull();
    const ino = statSync(sock).ino;

    const second = await startNamed(sock, 'second');
    expect(second).toBeNull();

    // Same file, same owner, still answering.
    expect(statSync(sock).ino).toBe(ino);
    const res = await resolveViaIpc(sock, { candidates: [] });
    expect(res).not.toBe(IPC_UNAVAILABLE);
    expect((res as PointerBlock).text).toBe('owner:first');
    expect(await (await newApi()).probeSocketOwner(sock)).toBe('live');
  });

  test.skipIf(!posix)('two starters racing on the same stale path yield exactly one server', async () => {
    const sock = tmpSock();
    writeFileSync(sock, ''); // stale leftover both starters will probe as dead
    const [a, b] = await Promise.all([startNamed(sock, 'a'), startNamed(sock, 'b')]);
    const winners = [a, b].filter((s) => s !== null);
    expect(winners.length).toBe(1);
    // The winner owns the path and answers; nothing else replaced it.
    const winnerTag = a ? 'owner:a' : 'owner:b';
    expect((await resolveViaIpc(sock, { candidates: [] }) as PointerBlock).text).toBe(winnerTag);
    expect((await newApi()).ownsSocketPath(sock, winners[0]!)).toBe(true);
    // The start lock is released once the winner is bound.
    expect(existsSync(`${sock}.starting`)).toBe(false);
  });

  test.skipIf(!posix)('start lock: a live holder blocks, a dead holder is reclaimed at once, an aged one by time; release is inode-checked', async () => {
    const api = await newApi();
    const sock = tmpSock();
    const lockDir = `${sock}.starting`;
    // Held by THIS (live) process, fresh: a start must yield null.
    const mine = api.acquireStartLock(sock);
    expect(mine).not.toBeNull();
    expect(mine!.held()).toBe(true);
    expect(await startNamed(sock, 'blocked')).toBeNull();
    // Release is inode-checked: once a reclaimer has put a NEW lock at the
    // path, the old holder's release must leave it alone.
    rmSync(lockDir, { recursive: true, force: true });
    mkdirSync(lockDir);
    expect(mine!.held()).toBe(false);
    mine!.release();
    expect(existsSync(lockDir)).toBe(true);
    rmSync(lockDir, { recursive: true, force: true });
    // A lock whose recorded owner is dead is reclaimed immediately, however
    // fresh — the crashed-starter case no longer costs anyone a wait.
    mkdirSync(lockDir);
    writeFileSync(join(lockDir, 'owner'), `${DEAD_PID}\n`);
    expect(await startNamed(sock, 'reclaimer')).not.toBeNull();
    expect(existsSync(lockDir)).toBe(false);
    // A lock whose owner is alive but older than START_LOCK_STALE_MS (a
    // starter suspended mid-start) is reclaimed by age.
    const sock2 = tmpSock();
    const lock2 = `${sock2}.starting`;
    mkdirSync(lock2);
    writeFileSync(join(lock2, 'owner'), `${process.pid}\n`);
    const old = new Date(Date.now() - api.START_LOCK_STALE_MS - 1000);
    utimesSync(lock2, old, old);
    expect(await startNamed(sock2, 'aged')).not.toBeNull();
    expect(existsSync(lock2)).toBe(false);
  });

  test.skipIf(!posix)('a dead leftover at the path is reaped and the path bound', async () => {
    const sock = tmpSock();
    writeFileSync(sock, ''); // a stale non-socket leftover, as after a crash
    expect(await (await newApi()).probeSocketOwner(sock)).toBe('dead');

    const server = await startNamed(sock, 'reaper');
    expect(server).not.toBeNull();
    expect(statSync(sock).isSocket()).toBe(true);
    const res = await resolveViaIpc(sock, { candidates: [] });
    expect((res as PointerBlock).text).toBe('owner:reaper');
  });

  test.skipIf(!posix)('probe verdicts: absent path, live path, closed path', async () => {
    const { probeSocketOwner } = await newApi();
    const sock = tmpSock();
    expect(await probeSocketOwner(sock)).toBe('dead'); // nothing there: the caller's unlink is a no-op
    const server = await startNamed(sock, 'live');
    expect(server).not.toBeNull();
    expect(await probeSocketOwner(sock)).toBe('live');
    server!.close();
    servers.splice(servers.indexOf(server!), 1);
    // Bun unlinks the path on close; a runtime that leaves the file behind
    // leaves a socket with a FRESH mtime and OUR live pid in its record, which
    // reads as live until the record no longer vouches for it.
    if (!existsSync(sock)) expect(await probeSocketOwner(sock)).toBe('dead');
  });

  test('refused-probe classification: owner record first, then the heartbeat, then the code', async () => {
    const { classifyRefusedProbe } = await newApi();
    const absent = { exists: false, isSocket: false, mtimeAgeMs: null, ownerAlive: null };
    const freshSock = { exists: true, isSocket: true, mtimeAgeMs: 1_000, ownerAlive: null };
    const staleSock = { exists: true, isSocket: true, mtimeAgeMs: 60_000, ownerAlive: null };
    const freshFile = { exists: true, isSocket: false, mtimeAgeMs: 1_000, ownerAlive: null };
    const deadOwnerFresh = { ...freshSock, ownerAlive: false };
    const liveOwnerStale = { ...staleSock, ownerAlive: true };
    const liveOwnerAncient = { exists: true, isSocket: true, mtimeAgeMs: 600_000, ownerAlive: true };
    const refusals = ['ENOENT', 'ECONNREFUSED', 'ENOTSOCK', undefined];
    const unrelated = ['EMFILE', 'ENFILE', 'EACCES', 'EPERM', 'EAGAIN', 'ETIMEDOUT', 'EBUSY'];
    for (const code of [...refusals, ...unrelated]) {
      // A record naming a dead pid settles it: the owner is gone, reap now.
      expect(classifyRefusedProbe(code, deadOwnerFresh)).toBe('dead');
      // A record naming a live pid vouches past the heartbeat window …
      expect(classifyRefusedProbe(code, liveOwnerStale)).toBe('live');
      // … a socket whose owner still heartbeats is a BUSY owner whatever the
      // code said (measured: a stalled Bun listener refuses with ENOENT).
      expect(classifyRefusedProbe(code, freshSock)).toBe('live');
    }
    // … but not forever: past OWNER_STALL_LIMIT_MS the code decides again.
    expect(classifyRefusedProbe('ECONNREFUSED', liveOwnerAncient)).toBe('dead');
    expect(classifyRefusedProbe('EMFILE', liveOwnerAncient)).toBe('unknown');
    // No record, no fresh heartbeat: a hard refusal proves nothing listens.
    for (const code of refusals) {
      expect(classifyRefusedProbe(code, absent)).toBe('dead');
      expect(classifyRefusedProbe(code, staleSock)).toBe('dead');
      expect(classifyRefusedProbe(code, freshFile)).toBe('dead'); // a regular-file leftover
    }
    // Errors that describe the prober, not the owner → never reap.
    for (const code of unrelated) {
      expect(classifyRefusedProbe(code, absent)).toBe('unknown');
      expect(classifyRefusedProbe(code, staleSock)).toBe('unknown');
      expect(classifyRefusedProbe(code, freshFile)).toBe('unknown');
    }
    // Both thresholds are parameters.
    expect(classifyRefusedProbe('ECONNREFUSED', freshSock, 500)).toBe('dead');
    expect(classifyRefusedProbe('ECONNREFUSED', liveOwnerStale, 30_000, 10_000)).toBe('dead');
  });

  test('liveness constants: several heartbeats fit inside the stale window, and the stall limit exceeds it', async () => {
    const { SOCKET_HEARTBEAT_MS, SOCKET_HEARTBEAT_STALE_MS, OWNER_STALL_LIMIT_MS, START_LOCK_STALE_MS } = await newApi();
    expect(SOCKET_HEARTBEAT_MS).toBeGreaterThan(0);
    expect(SOCKET_HEARTBEAT_STALE_MS).toBeGreaterThanOrEqual(3 * SOCKET_HEARTBEAT_MS);
    expect(OWNER_STALL_LIMIT_MS).toBeGreaterThan(SOCKET_HEARTBEAT_STALE_MS);
    expect(START_LOCK_STALE_MS).toBeGreaterThan(1_000);
  });

  test('processAlive: this process exists, a pid nobody has does not', async () => {
    const { processAlive } = await newApi();
    expect(processAlive(process.pid)).toBe(true);
    expect(processAlive(DEAD_PID)).toBe(false);
    expect(processAlive(0)).toBeNull();
  });

  test.skipIf(!posix)('the owner heartbeats its socket file while it owns the path', async () => {
    const sock = tmpSock();
    const server = await startResolveIpcServer(sock, { resolve: async () => blockNamed('hb') }, { heartbeatMs: 40 });
    expect(server).not.toBeNull();
    servers.push(server!);
    const m0 = statSync(sock).mtimeMs;
    await new Promise((r) => setTimeout(r, 160));
    expect(statSync(sock).mtimeMs).toBeGreaterThan(m0);
    // Freshly heartbeaten → a refusal would read as live, never dead.
    const { probeFileInfo, classifyRefusedProbe } = await newApi();
    expect(classifyRefusedProbe('ECONNREFUSED', probeFileInfo(sock))).toBe('live');
  });

  test.skipIf(!posix)('the owner records itself beside the socket; only its own shutdown removes the record', async () => {
    const api = await newApi();
    const sock = tmpSock();
    const first = await startNamed(sock, 'first');
    expect(first).not.toBeNull();
    expect(api.readOwnerSidecar(sock)).toEqual({ pid: process.pid, ino: statSync(sock).ino });
    expect(api.probeFileInfo(sock).ownerAlive).toBe(true);
    // Displaced (the pre-#4896 steal): the newcomer's record replaces ours,
    // and our shutdown leaves both its socket and its record alone.
    unlinkSync(sock);
    const second = await startNamed(sock, 'second');
    expect(second).not.toBeNull();
    expect(api.readOwnerSidecar(sock)!.ino).toBe(statSync(sock).ino);
    expect(api.closeResolveIpcServer(sock, first!)).toBe('left-open-displaced');
    expect(existsSync(api.ownerSidecarPath(sock))).toBe(true);
    // The real owner's shutdown removes its record with the socket.
    expect(api.closeResolveIpcServer(sock, second!)).toBe('closed');
    servers.splice(servers.indexOf(second!), 1);
    expect(existsSync(sock)).toBe(false);
    expect(existsSync(api.ownerSidecarPath(sock))).toBe(false);
    first!.close();
    servers.splice(servers.indexOf(first!), 1);
  });

  test.skipIf(!posix)('a crashed owner is reaped at once: its record names a dead pid, however fresh the socket', async () => {
    const api = await newApi();
    const sock = tmpSock();
    // A child binds through startResolveIpcServer (so it writes its record)
    // and exits without closing — a provider killed mid-flight.
    const child = Bun.spawnSync([process.execPath, '-e',
      `import(${JSON.stringify(MODULE_PATH)}).then(async (m) => { const s = await m.startResolveIpcServer(process.argv[1], async () => null); process.exit(s ? 0 : 3); });`,
      sock]);
    expect(child.exitCode).toBe(0);
    expect(statSync(sock).isSocket()).toBe(true);
    const record = api.readOwnerSidecar(sock);
    expect(record).not.toBeNull();
    expect(record!.pid).not.toBe(process.pid);
    expect(api.processAlive(record!.pid)).toBe(false);
    expect(api.probeFileInfo(sock).ownerAlive).toBe(false);
    // Fresh mtime, but the owner is gone: dead now, not in 30 s.
    expect(await api.probeSocketOwner(sock)).toBe('dead');
    const replacement = await startNamed(sock, 'replacement');
    expect(replacement).not.toBeNull();
    expect(api.readOwnerSidecar(sock)!.pid).toBe(process.pid);
    expect((await resolveViaIpc(sock, { candidates: [] }) as PointerBlock).text).toBe('owner:replacement');
  });

  test.skipIf(!posix)('a socket left without a record: live while its mtime is fresh, reaped once stale', async () => {
    const api = await newApi();
    const sock = tmpSock();
    leaveBareSocket(sock);
    // Fresh mtime, no record (a pre-record owner, or one that died before
    // writing it): indistinguishable from a busy owner whose connect was
    // refused, so a second start yields and nobody reaps it yet — the
    // bootstrap verifier sees a provider too.
    expect(api.probeFileInfo(sock).ownerAlive).toBeNull();
    expect(await api.probeSocketOwner(sock)).toBe('live');
    expect(await api.socketHasLiveListener(sock)).toBe(true);
    expect(await startNamed(sock, 'too-early')).toBeNull();
    // Stale mtime (older than the heartbeat window): reaped and bound.
    const old = new Date(Date.now() - api.SOCKET_HEARTBEAT_STALE_MS - 1000);
    utimesSync(sock, old, old);
    expect(await api.probeSocketOwner(sock)).toBe('dead');
    const server = await startNamed(sock, 'reaper');
    expect(server).not.toBeNull();
    expect((await resolveViaIpc(sock, { candidates: [] }) as PointerBlock).text).toBe('owner:reaper');
  });

  test.skipIf(!posix)('a stalled owner is not reaped while its process lives, even past the heartbeat window', async () => {
    const api = await newApi();
    const sock = tmpSock();
    // A socket file nothing listens behind …
    leaveBareSocket(sock);
    // … that THIS live process claims: refused connects must read as a busy
    // owner, however stale the heartbeat.
    writeFileSync(api.ownerSidecarPath(sock), `${JSON.stringify({ pid: process.pid, ino: statSync(sock).ino })}\n`);
    const stale = new Date(Date.now() - api.SOCKET_HEARTBEAT_STALE_MS - 5_000);
    utimesSync(sock, stale, stale);
    expect(api.probeFileInfo(sock).ownerAlive).toBe(true);
    expect(await api.probeSocketOwner(sock)).toBe('live');
    expect(await startNamed(sock, 'intruder')).toBeNull();
    // A record naming another inode is a previous owner's and does not vouch.
    writeFileSync(api.ownerSidecarPath(sock), `${JSON.stringify({ pid: process.pid, ino: statSync(sock).ino + 1 })}\n`);
    expect(api.probeFileInfo(sock).ownerAlive).toBeNull();
    expect(await api.probeSocketOwner(sock)).toBe('dead');
    // Past the stall limit the record no longer vouches either: a stall that
    // long, or a reused pid, is treated as gone.
    writeFileSync(api.ownerSidecarPath(sock), `${JSON.stringify({ pid: process.pid, ino: statSync(sock).ino })}\n`);
    const ancient = new Date(Date.now() - api.OWNER_STALL_LIMIT_MS - 5_000);
    utimesSync(sock, ancient, ancient);
    expect(await api.probeSocketOwner(sock)).toBe('dead');
    expect(await startNamed(sock, 'reaper')).not.toBeNull();
  });

  test.skipIf(!posix)('shutdown unlinks only the socket file this server created', async () => {
    const { ownsSocketPath, unlinkSocketIfOwned, closeResolveIpcServer, probeSocketOwner } = await newApi();
    const sock = tmpSock();
    const first = await startNamed(sock, 'first');
    expect(first).not.toBeNull();
    const firstIno = statSync(sock).ino;

    // Simulate the pre-#4896 steal: the path is replaced under the live owner.
    unlinkSync(sock);
    const second = await startNamed(sock, 'second');
    expect(second).not.toBeNull();
    const secondIno = statSync(sock).ino;
    expect(secondIno).not.toBe(firstIno);

    // The displaced owner's shutdown must leave the newcomer's socket alone —
    // including NOT calling server.close(), which under Bun unlinks the path
    // regardless of who owns it (measured 1.3.13).
    expect(ownsSocketPath(sock, first!)).toBe(false);
    expect(unlinkSocketIfOwned(sock, first!)).toBe(false);
    expect(closeResolveIpcServer(sock, first!)).toBe('left-open-displaced');
    expect(existsSync(sock)).toBe(true);
    expect(statSync(sock).ino).toBe(secondIno);
    expect((await resolveViaIpc(sock, { candidates: [] }) as PointerBlock).text).toBe('owner:second');

    // The real owner's shutdown closes and reaps it (Bun unlinks on close;
    // the explicit reap is the Node fallback and must be a harmless no-op).
    expect(ownsSocketPath(sock, second!)).toBe(true);
    expect(closeResolveIpcServer(sock, second!)).toBe('closed');
    servers.splice(servers.indexOf(second!), 1);
    expect(existsSync(sock)).toBe(false);
    expect(await probeSocketOwner(sock)).toBe('dead');
    // The displaced listener is still alive in-process (left open on purpose);
    // it dies with the process. Close it here so the test does not leak it.
    first!.close();
    servers.splice(servers.indexOf(first!), 1);
  });

  test.skipIf(!posix)('a server whose ownership was never recorded is left open, not closed', async () => {
    const { ownsSocketPath, closeResolveIpcServer } = await newApi();
    const sock = tmpSock();
    const server = await startNamed(sock, 'anon');
    expect(server).not.toBeNull();
    // Strip the recorded inode to simulate a stat failure at bind time.
    delete (server as unknown as Record<symbol, unknown>)[Symbol.for('gbrain.resolveIpc.ownedSocketInode')];
    expect(ownsSocketPath(sock, server!)).toBe(false);
    expect(closeResolveIpcServer(sock, server!)).toBe('left-open-unknown');
    expect(existsSync(sock)).toBe(true);
  });
});
