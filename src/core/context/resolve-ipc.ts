/**
 * Retrieval Reflex — resolve IPC (issue #1981, D9=C) + turn-context IPC v2
 * (agent-bootstrap plan: ENG-3, A9, S3#6, G11, CX2-10).
 *
 * PGLite is single-connection: `gbrain serve` holds the one connection for its
 * lifetime, so the context engine cannot open its own and must NOT shell out to
 * a subprocess (that would force-steal the lock past the 5-min staleness window
 * and crash the brain — see plan D9 rejected option). Instead, `serve`
 * optionally listens on a local unix-domain socket and answers NARROW requests
 * using the connection it already owns. Both ends are gbrain code; raw SQL
 * never crosses the wire (closes the trust hole).
 *
 * Protocol: newline-delimited JSON. One request line, one response line.
 * Requests form a discriminated union on `kind`; ABSENT kind means 'resolve'
 * so every v1 client keeps working against a v2 server unchanged [ENG-3]:
 *
 *   resolve (v1, secret-free):
 *     req:  { kind?: 'resolve', candidates, priorContextText?, maxPointers?, sourceId? }
 *     resp: { ok: true, block: PointerBlock | null } | { ok: false, error }
 *
 *   turn_context (v2, secret-gated [S3#6], source-bound [CX2-10]):
 *     req:  { kind: 'turn_context', protocol: 2, secret, window, priorContextText?,
 *             sessionId?, sourceId?, maxBytes? }
 *     resp: { ok, protocol: 2, block?, degradedReason?, error? }
 *
 * The protocol:2 echo on every turn_context response is the stale-serve
 * detector [A9]: a v1 server answers a turn_context request as a resolve
 * request (`{ok:true, block:null}`, no echo) and the client degrades to a
 * typed { degraded: 'stale_serve' } instead of trusting the empty block.
 *
 *   sync_start / sync_status / sync_abort (secret-gated, protocol:2):
 *     serve-delegated sync — a `gbrain sync` CLI that finds a live serve
 *     holding the PGLite lock delegates the run through these kinds instead
 *     of failing on LiveServeLockError. Wire shapes + option validation live
 *     in sync-ipc.ts; execution lives in serve-sync-runner.ts. Start+poll
 *     (never a held-open connection): every request stays one line / one
 *     response, and an old serve answers `unknown_kind:sync_start` so the
 *     client degrades to the documented stop-the-serve refusal.
 *
 *   sweep_start / sweep_status (secret-gated, protocol:2) — #677:
 *     serve-delegated maintenance sweep, the same start+poll shape as the
 *     sync kinds (no abort — a sweep is a bounded run). Wire shapes in
 *     sweep-ipc.ts; execution in serve-sweep-runner.ts; CLI half in
 *     commands/sweep-delegate.ts.
 *
 * Local-only (unix socket in a 0700 dir on the brain's data dir, socket mode
 * 0600 set before readiness is announced) — no network surface.
 */

import net from 'node:net';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  existsSync,
  unlinkSync,
  statSync,
  renameSync,
  rmSync,
  utimesSync,
  chmodSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { join, dirname } from 'node:path';
import { configDir } from '../config.ts';
import type { EntityCandidate } from './entity-salience.ts';
import type { WindowTurn } from './entity-salience.ts';
import type { PointerBlock } from './retrieval-reflex.ts';
import type { TurnContextResult } from './turn-context.ts';
import type {
  SyncAbortRequest,
  SyncAbortResponse,
  SyncStartRequest,
  SyncStartResponse,
  SyncStatusRequest,
  SyncStatusResponse,
} from './sync-ipc.ts';
import type {
  SweepStartRequest,
  SweepStartResponse,
  SweepStatusRequest,
  SweepStatusResponse,
} from './sweep-ipc.ts';

const SOCK_NAME = '.gbrain-resolve.sock';
const SECRET_NAME = '.gbrain-ipc-secret';
/** Per-kind budgets [G11]: resolve keeps its legacy 250ms client timeout. */
const CLIENT_TIMEOUT_MS = 250;
/** turn_context does real assembly work — wider client budget (still <1s). */
export const TURN_CONTEXT_CLIENT_TIMEOUT_MS = 600;
/** Server-side self-budget for turn_context assembly (< client timeout). */
export const TURN_CONTEXT_SERVER_BUDGET_MS = 400;
/**
 * v0.45.7 ambient recall — context_pack budgets. Packs build entity CARDS
 * (heavier than turn_context's three arms), and their consumer is the
 * session-start hook (1.5s self-deadline, 5s harness timeout), so they get a
 * wider budget. The server passes its budget into the assembler as a
 * wall-clock deadline, so overrun returns a PARTIAL pack (degradedReason
 * 'deadline'), never an empty hard failure (eng 4A).
 */
export const CONTEXT_PACK_CLIENT_TIMEOUT_MS = 1000;
/** Assembler deadline. Backstop = +200; client 1000 leaves a real transport
 * margin (adversarial review: 800+200 == client timeout was zero margin). */
export const CONTEXT_PACK_SERVER_BUDGET_MS = 600;
/**
 * Delegated-sync kinds are O(1) in-memory registrations/reads — no assembly
 * work, so no server-side budget race. start is a touch wider: its handler
 * validates options and registers the job before answering, and a serve loop
 * mid-import can sit on a long WASM statement before dispatching.
 */
export const SYNC_START_CLIENT_TIMEOUT_MS = 1500;
export const SYNC_STATUS_CLIENT_TIMEOUT_MS = 1000;
export const SYNC_ABORT_CLIENT_TIMEOUT_MS = 1000;
/**
 * Delegated-sweep kinds (#677) — same O(1) register/read shape as the sync
 * kinds, same budgets.
 */
export const SWEEP_START_CLIENT_TIMEOUT_MS = 1500;
export const SWEEP_STATUS_CLIENT_TIMEOUT_MS = 1000;
const MAX_MSG_BYTES = 256 * 1024;

/** Marker the client returns when no server is reachable (vs. a real null result). */
export const IPC_UNAVAILABLE = Symbol('ipc-unavailable');

// ── Request / response types (discriminated union, named responses) ───────

export interface ResolveRequest {
  /** Absent kind means 'resolve' — v1 clients never send it (back-compat). */
  kind?: 'resolve';
  candidates: EntityCandidate[];
  priorContextText?: string;
  maxPointers?: number;
  /**
   * Optional source claim. On a server started with opts.boundSourceId, any
   * OTHER value is rejected with 'source_mismatch' [CX2-10] — same binding as
   * turn_context. Unbound (legacy positional) servers pass it through.
   */
  sourceId?: string;
  /** v0.43 (#2095, codex D7): suppression mode — 'slug-only' under windowing. */
  suppression?: 'slug-and-title' | 'slug-only';
  /**
   * 2026-08 fix wave: the volunteer stage's wide ungated pool resolve. The
   * binding's onDelivered skips delivery logging for probe requests (the pool
   * is not injected pointers; gated survivors log via volunteer-events). An
   * older serve ignores the field — accepted minor mixed-version stat noise.
   */
  probe?: 'volunteer';
  /**
   * v0.46.15: lexical-arms kill switch. Either side may disable: a client
   * `false` wins; otherwise the server applies its own file-config gate.
   */
  lexicalArms?: boolean;
}

export interface TurnContextRequest {
  kind: 'turn_context';
  /** Protocol version claim; the server echoes it so clients can detect a stale serve [A9]. */
  protocol: 2;
  /** Shared secret from `<dataDir>/.gbrain-ipc-secret` [S3#6]. resolve stays secret-free. */
  secret: string;
  /** Recent conversation turns, oldest → newest (trimmed oldest-first to fit the message cap [G11]). */
  window: WindowTurn[];
  priorContextText?: string;
  sessionId?: string;
  /** Optional source claim — the server REJECTS any value other than its bound source [CX2-10]. */
  sourceId?: string;
  maxBytes?: number;
  /**
   * Event-attribution channel for the delivery-point feedback loop (harness
   * hook adapters): the server logs the delivered block's volunteered pages /
   * pointers to context_volunteer_events under this channel so
   * `volunteer-context --stats` and the volunteer_channels doctor check see
   * per-harness firing. Validated server-side against the known channel set;
   * absent/unknown → 'claude-code' (the only harness bootstrap registers
   * hooks for today). Additive: old servers ignore it (no logging — the
   * pre-feedback-loop status quo).
   */
  channel?: string;
}

/**
 * v0.45.7 ambient recall — boundary context pack over IPC. Two modes:
 *   - assembly (default): the server resolves standing entities (request
 *     `entities` + window extraction + the session row's banked set), assembles
 *     a pack (cards + open threads + hot facts + since-delta vs the session
 *     cursor), advances the cursor, and returns the injectable block.
 *   - bankOnly: PreCompact banking — extract entities from `window`, merge
 *     them into the session row's standing set, return an empty block. The
 *     post-compaction SessionStart (source=compact) then serves a warm pack.
 * Same secret + source-binding posture as turn_context. World-only ALWAYS
 * (the push path never widens — include_private is a pull-verb affordance).
 */
export interface ContextPackRequest {
  kind: 'context_pack';
  protocol: 2;
  secret: string;
  sessionId?: string;
  sourceId?: string;
  /** Explicit standing entities (names/slugs); merged with the session row's banked set. */
  entities?: string[];
  /** Recent turns for entity extraction (compact banking / cold-start fallback). */
  window?: WindowTurn[];
  maxBytes?: number;
  /** Trigger discriminator ('session-start:<source>' | 'compact-bank').
   * RESERVED: carried on the wire for future server-side telemetry; no
   * server-side consumer yet (the hook-side heartbeat is the current
   * observability channel). */
  trigger?: string;
  /** PreCompact banking mode: persist entities, skip assembly. */
  bankOnly?: boolean;
  /**
   * Cathedral 5 (additive, bankOnly companion): BASENAME of a corpus segment
   * this hook just banked — serve schedules a prompt checkpoint harvest of it
   * (fire-and-forget; the ack never waits on the LLM). Version-skew tolerant
   * BY DESIGN: an old serve destructures known fields and ignores this one
   * (today's behavior); the sweep backstop still extracts the segment.
   */
  flushCorpusFile?: string;
  /**
   * Cathedral 5 (additive, read-only): return the session's checkpoint
   * manifest links — no assembly, no cursor advance, no banking. Used by the
   * OpenClaw assemble poll.
   */
  manifestOnly?: boolean;
}

export type IpcRequest =
  | ResolveRequest
  | TurnContextRequest
  | ContextPackRequest
  | SyncStartRequest
  | SyncStatusRequest
  | SyncAbortRequest
  | SweepStartRequest
  | SweepStatusRequest;

export interface ResolveResponse {
  ok: boolean;
  block?: PointerBlock | null;
  error?: string;
}

export interface TurnContextResponse {
  ok: boolean;
  /** Always 2 on a v2 server. A response WITHOUT this echo is a stale (v1) serve [A9]. */
  protocol: 2;
  block?: TurnContextResult | null;
  degradedReason?: string;
  error?: string;
}

export interface ContextPackResponse {
  ok: boolean;
  /** Always 2 on a v2 server (stale-serve detector, same as turn_context [A9]). */
  protocol: 2;
  block?: TurnContextResult | null;
  degradedReason?: string;
  error?: string;
}

export type ResolveHandler = (req: ResolveRequest) => Promise<PointerBlock | null>;
export type TurnContextHandler = (req: TurnContextRequest) => Promise<TurnContextResult | null>;
export type ContextPackHandler = (req: ContextPackRequest) => Promise<TurnContextResult | null>;

export type SyncStartIpcHandler = (req: SyncStartRequest) => SyncStartResponse | Promise<SyncStartResponse>;
export type SyncStatusIpcHandler = (req: SyncStatusRequest) => SyncStatusResponse | Promise<SyncStatusResponse>;
export type SyncAbortIpcHandler = (req: SyncAbortRequest) => SyncAbortResponse | Promise<SyncAbortResponse>;
export type SweepStartIpcHandler = (req: SweepStartRequest) => SweepStartResponse | Promise<SweepStartResponse>;
export type SweepStatusIpcHandler = (req: SweepStatusRequest) => SweepStatusResponse | Promise<SweepStatusResponse>;

/** Handler MAP replacing the single closure [ENG-3]. */
export interface IpcHandlers {
  resolve: ResolveHandler;
  turn_context?: TurnContextHandler;
  context_pack?: ContextPackHandler;
  sync_start?: SyncStartIpcHandler;
  sync_status?: SyncStatusIpcHandler;
  sync_abort?: SyncAbortIpcHandler;
  sweep_start?: SweepStartIpcHandler;
  sweep_status?: SweepStatusIpcHandler;
}

export interface IpcServerOpts {
  /**
   * v0.43 (#2095, red-team): fired ONLY after the resolve response was
   * successfully written to the client — the accept-side seam for
   * reflex-channel feedback logging. A block the client never received
   * (timeout, dead socket) was never injected into a prompt and must not
   * count as "volunteered".
   */
  onDelivered?: (block: PointerBlock, req: ResolveRequest) => void;
  /**
   * turn_context sibling of onDelivered — fired ONLY after an ok
   * turn_context response with a non-empty block was successfully written to
   * the client. This is the #2095 feedback-loop seam for the hook lane: the
   * callback logs the block's post-trim volunteered pages + pointers to
   * context_volunteer_events under req.channel. Same red-team rule as
   * onDelivered: a block the client's budget abandoned was never injected
   * and must not be counted.
   */
  onTurnContextDelivered?: (result: TurnContextResult, req: TurnContextRequest) => void;
  /**
   * The server's registered source [CX2-10]. turn_context requests naming a
   * DIFFERENT sourceId are rejected with 'source_mismatch'; the handler always
   * assembles against the bound source regardless.
   */
  boundSourceId?: string;
  /**
   * Shared secret value for turn_context [S3#6] (from ensureIpcSecret).
   * When a turn_context handler is registered without a secret, every
   * turn_context request is rejected 'unauthorized' (fail closed).
   */
  secret?: string;
  /**
   * Owner heartbeat period for the socket file's mtime (see
   * SOCKET_HEARTBEAT_MS). Test seam only — production callers leave it unset.
   */
  heartbeatMs?: number;
}

/** Canonical socket path for a PGLite data dir. */
export function resolveSocketPath(dataDir: string): string {
  return join(dataDir, SOCK_NAME);
}

// -- Engine-uniform paths (#4245, TODOS "engine-uniform IPC listener") --

/**
 * IPC home for brains with no data dir: `~/.gbrain/run` (GBRAIN_HOME
 * honored via configDir). Created 0700 by the server bind / secret
 * provision paths — never world-visible.
 */
export function ipcRunDir(): string {
  return join(configDir(), 'run');
}

/** First 12 hex chars of sha256(value) — path key that never embeds the URL's credentials. */
function hash12(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 12);
}

/** Minimal config slice the engine-uniform path resolvers key on (loadConfig's shape). */
export interface IpcPathConfig {
  engine?: 'postgres' | 'pglite';
  database_path?: string;
  database_url?: string;
}

/**
 * Canonical socket path for a brain CONFIG (engine-uniform, #4245).
 * PGLite keeps the data-dir socket (wire location unchanged — old serves
 * and hooks keep pairing); Postgres gets
 * `~/.gbrain/run/resolve-<hash12(database_url)>.sock` so two brains on one
 * machine never share a socket. Returns null when the config carries no
 * keying material (no config at all, thin-client remote, or a postgres
 * config with no URL) — callers degrade, never guess.
 *
 * Engine is checked FIRST: a postgres config carrying a LEFTOVER
 * database_path must not key off the path — there is no PGLite brain (and
 * no serve) behind it (v0.45.7 gate, preserved).
 *
 * Multi-serve note: on Postgres several serves for the SAME database_url
 * share this path; the first LIVE provider wins — a later serve probes the
 * socket, finds a live owner, and defers (null binding) instead of unlinking
 * it (#4896). Bound-source rejection [CX2-10] still applies per request.
 */
export function resolveSocketPathForConfig(cfg: IpcPathConfig | null | undefined): string | null {
  if (!cfg) return null;
  if (cfg.engine === 'pglite' && cfg.database_path) return resolveSocketPath(cfg.database_path);
  if (cfg.engine === 'postgres' && cfg.database_url) {
    return join(ipcRunDir(), `resolve-${hash12(cfg.database_url)}.sock`);
  }
  return null;
}

/**
 * Canonical shared-secret path for a brain config — same engine-uniform
 * keying as resolveSocketPathForConfig (data dir on PGLite, hash12-keyed
 * run-dir file on Postgres). Null = no keying material.
 */
export function ipcSecretPathForConfig(cfg: IpcPathConfig | null | undefined): string | null {
  if (!cfg) return null;
  if (cfg.engine === 'pglite' && cfg.database_path) return ipcSecretPath(cfg.database_path);
  if (cfg.engine === 'postgres' && cfg.database_url) {
    return join(ipcRunDir(), `secret-${hash12(cfg.database_url)}`);
  }
  return null;
}

/**
 * Server-side (engine-uniform): ensure the secret at the config-keyed path.
 * Null = no keying material (caller starts no listener); throws only when
 * the file can neither be read nor created (turn_context disabled, never
 * "skip auth" — same contract as ensureIpcSecret).
 */
export function ensureIpcSecretForConfig(cfg: IpcPathConfig | null | undefined): string | null {
  const p = ipcSecretPathForConfig(cfg);
  if (!p) return null;
  return ensureIpcSecretAtPath(p);
}

/** Client-side (engine-uniform): read the config-keyed secret; null when absent. */
export function readIpcSecretForConfig(cfg: IpcPathConfig | null | undefined): string | null {
  const p = ipcSecretPathForConfig(cfg);
  if (!p) return null;
  try {
    const s = readFileSync(p, 'utf8').trim();
    return s || null;
  } catch {
    return null;
  }
}

// ── Shared secret [S3#6] ──────────────────────────────────────────────────

/** Canonical shared-secret file path for a PGLite data dir. */
export function ipcSecretPath(dataDir: string): string {
  return join(dataDir, SECRET_NAME);
}

/**
 * Server-side: read the shared secret, creating a fresh 32-byte random hex
 * secret at `<dataDir>/.gbrain-ipc-secret` (mode 0600) if absent. Throws only
 * when the file can neither be read nor created (callers treat that as
 * "turn_context disabled", never as "skip auth").
 */
export function ensureIpcSecret(dataDir: string): string {
  return ensureIpcSecretAtPath(ipcSecretPath(dataDir));
}

/** Path-keyed body shared by the data-dir and config-keyed secret provisioners. */
function ensureIpcSecretAtPath(p: string): string {
  try {
    const existing = readFileSync(p, 'utf8').trim();
    if (existing) {
      try { chmodSync(p, 0o600); } catch { /* best effort */ }
      return existing;
    }
  } catch { /* absent or unreadable — create below */ }
  const secret = randomBytes(32).toString('hex');
  mkdirSync(dirname(p), { recursive: true, mode: 0o700 });
  writeFileSync(p, secret + '\n', { mode: 0o600 });
  try { chmodSync(p, 0o600); } catch { /* best effort */ }
  return secret;
}

/** Client-side: read the shared secret; null when absent (no server has created it). */
export function readIpcSecret(dataDir: string): string | null {
  try {
    const s = readFileSync(ipcSecretPath(dataDir), 'utf8').trim();
    return s || null;
  } catch {
    return null;
  }
}

/** Constant-time secret comparison (length mismatch short-circuits — leaks length only). */
function secretMatches(candidate: unknown, expected: string): boolean {
  if (typeof candidate !== 'string' || !candidate || !expected) return false;
  const a = Buffer.from(candidate, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// ── Clients ───────────────────────────────────────────────────────────────

/**
 * v1 client: ship candidates to a running serve, get pointers back. Returns
 * IPC_UNAVAILABLE when no server is listening (caller falls through the ladder);
 * a real PointerBlock | null otherwise. Never throws — fail-soft to UNAVAILABLE.
 */
export async function resolveViaIpc(
  socketPath: string,
  req: ResolveRequest,
): Promise<PointerBlock | null | typeof IPC_UNAVAILABLE> {
  const resp = await roundTrip(socketPath, JSON.stringify(req), CLIENT_TIMEOUT_MS);
  if (resp === IPC_UNAVAILABLE) return IPC_UNAVAILABLE;
  if (resp && (resp as ResolveResponse).ok) return (resp as ResolveResponse).block ?? null;
  return IPC_UNAVAILABLE;
}

/** Client-facing turn_context request shape (kind/protocol are filled in by the helper). */
export type TurnContextClientRequest = Omit<TurnContextRequest, 'kind' | 'protocol'>;

/**
 * Typed degraded marker for a v1 server answering a v2 request [A9] — the
 * response parsed but carried no protocol echo, so its (empty) block must
 * not be trusted as "nothing relevant".
 */
export interface TurnContextStaleServe {
  degraded: 'stale_serve';
}

export type TurnContextIpcResult =
  | TurnContextResponse
  | TurnContextStaleServe
  | typeof IPC_UNAVAILABLE;

/**
 * v2 client: request an assembled turn-context block from a running serve.
 * Mirrors resolveViaIpc's fail-soft style — socket/timeout/parse trouble is
 * IPC_UNAVAILABLE, a protocol-less response is { degraded: 'stale_serve' },
 * everything else is the server's typed TurnContextResponse (including
 * ok:false rejections like 'unauthorized' / 'source_mismatch', which callers
 * may want to surface). Never throws.
 *
 * [G11] The request is clamped below the 256KB message cap before send by
 * trimming window turns oldest-first.
 */
export async function requestTurnContext(
  socketPath: string,
  req: TurnContextClientRequest,
  opts: { timeoutMs?: number } = {},
): Promise<TurnContextIpcResult> {
  const full: TurnContextRequest = {
    kind: 'turn_context',
    protocol: 2,
    ...req,
    window: Array.isArray(req.window) ? [...req.window] : [],
  };
  let line = JSON.stringify(full);
  // Trim to the message cap [G11] in priority order: the ADVISORY dedupe
  // payload (priorContextText) is dropped BEFORE any essential window turn —
  // evicting the window first would silently hollow out candidate extraction
  // (empty blocks with ok:true) to preserve a hint. Then window turns,
  // oldest-first.
  if (Buffer.byteLength(line, 'utf8') + 1 > MAX_MSG_BYTES && full.priorContextText) {
    delete full.priorContextText;
    line = JSON.stringify(full);
  }
  while (Buffer.byteLength(line, 'utf8') + 1 > MAX_MSG_BYTES && full.window.length > 0) {
    full.window.shift();
    line = JSON.stringify(full);
  }
  if (Buffer.byteLength(line, 'utf8') + 1 > MAX_MSG_BYTES) return IPC_UNAVAILABLE;

  const resp = await roundTrip(socketPath, line, opts.timeoutMs ?? TURN_CONTEXT_CLIENT_TIMEOUT_MS);
  if (resp === IPC_UNAVAILABLE) return IPC_UNAVAILABLE;
  if (!resp || typeof resp !== 'object') return IPC_UNAVAILABLE;
  // Stale-serve detection [A9]: no protocol echo → a v1 server handled this
  // as a resolve request; its block is meaningless for turn_context.
  if ((resp as { protocol?: unknown }).protocol !== 2) return { degraded: 'stale_serve' };
  return resp as TurnContextResponse;
}

/** Client-facing context_pack request shape (kind/protocol filled in by the helper). */
export type ContextPackClientRequest = Omit<ContextPackRequest, 'kind' | 'protocol'>;

export type ContextPackIpcResult =
  | ContextPackResponse
  | TurnContextStaleServe
  | typeof IPC_UNAVAILABLE;

/**
 * v0.45.7 client: request a boundary context pack (or a PreCompact entity bank)
 * from a running serve. Same fail-soft ladder as requestTurnContext: transport
 * trouble → IPC_UNAVAILABLE; missing protocol echo → stale_serve; otherwise
 * the server's typed response. Never throws. Window trims oldest-first under
 * the message cap [G11].
 */
export async function requestContextPack(
  socketPath: string,
  req: ContextPackClientRequest,
  opts: { timeoutMs?: number } = {},
): Promise<ContextPackIpcResult> {
  const full: ContextPackRequest = {
    kind: 'context_pack',
    protocol: 2,
    ...req,
    ...(req.window ? { window: [...req.window] } : {}),
  };
  let line = JSON.stringify(full);
  while (
    Buffer.byteLength(line, 'utf8') + 1 > MAX_MSG_BYTES &&
    Array.isArray(full.window) &&
    full.window.length > 0
  ) {
    full.window.shift();
    line = JSON.stringify(full);
  }
  if (Buffer.byteLength(line, 'utf8') + 1 > MAX_MSG_BYTES) return IPC_UNAVAILABLE;

  const resp = await roundTrip(socketPath, line, opts.timeoutMs ?? CONTEXT_PACK_CLIENT_TIMEOUT_MS);
  if (resp === IPC_UNAVAILABLE) return IPC_UNAVAILABLE;
  if (!resp || typeof resp !== 'object') return IPC_UNAVAILABLE;
  if ((resp as { protocol?: unknown }).protocol !== 2) return { degraded: 'stale_serve' };
  return resp as ContextPackResponse;
}

// ── Delegated-sync clients ────────────────────────────────────────────────

/** Client-facing shapes (kind/protocol filled in by the helpers). */
export type SyncStartClientRequest = Omit<SyncStartRequest, 'kind' | 'protocol'>;
export type SyncStatusClientRequest = Omit<SyncStatusRequest, 'kind' | 'protocol'>;
export type SyncAbortClientRequest = Omit<SyncAbortRequest, 'kind' | 'protocol'>;

export type SyncStartIpcResult = SyncStartResponse | TurnContextStaleServe | typeof IPC_UNAVAILABLE;
export type SyncStatusIpcResult = SyncStatusResponse | TurnContextStaleServe | typeof IPC_UNAVAILABLE;
export type SyncAbortIpcResult = SyncAbortResponse | TurnContextStaleServe | typeof IPC_UNAVAILABLE;

/**
 * Delegated-sync clients: same fail-soft ladder as requestTurnContext —
 * transport trouble → IPC_UNAVAILABLE; a response without the protocol echo
 * (a pre-delegation serve answered `unknown_kind:*` or treated the line as a
 * resolve request) → { degraded: 'stale_serve' }; otherwise the server's
 * typed response, INCLUDING ok:false rejections ('busy', 'unauthorized',
 * 'unknown_job', …) that the sync CLI turns into remediation text. Never throw.
 */
export async function requestSyncStart(
  socketPath: string,
  req: SyncStartClientRequest,
  opts: { timeoutMs?: number } = {},
): Promise<SyncStartIpcResult> {
  const line = JSON.stringify({ kind: 'sync_start', protocol: 2, ...req } satisfies SyncStartRequest);
  return syncRoundTrip<SyncStartResponse>(socketPath, line, opts.timeoutMs ?? SYNC_START_CLIENT_TIMEOUT_MS);
}

export async function requestSyncStatus(
  socketPath: string,
  req: SyncStatusClientRequest,
  opts: { timeoutMs?: number } = {},
): Promise<SyncStatusIpcResult> {
  const line = JSON.stringify({ kind: 'sync_status', protocol: 2, ...req } satisfies SyncStatusRequest);
  return syncRoundTrip<SyncStatusResponse>(socketPath, line, opts.timeoutMs ?? SYNC_STATUS_CLIENT_TIMEOUT_MS);
}

export async function requestSyncAbort(
  socketPath: string,
  req: SyncAbortClientRequest,
  opts: { timeoutMs?: number } = {},
): Promise<SyncAbortIpcResult> {
  const line = JSON.stringify({ kind: 'sync_abort', protocol: 2, ...req } satisfies SyncAbortRequest);
  return syncRoundTrip<SyncAbortResponse>(socketPath, line, opts.timeoutMs ?? SYNC_ABORT_CLIENT_TIMEOUT_MS);
}

// ── Delegated-sweep clients (#677) — same fail-soft ladder as sync ─────────

export type SweepStartClientRequest = Omit<SweepStartRequest, 'kind' | 'protocol'>;
export type SweepStatusClientRequest = Omit<SweepStatusRequest, 'kind' | 'protocol'>;

export type SweepStartIpcResult = SweepStartResponse | TurnContextStaleServe | typeof IPC_UNAVAILABLE;
export type SweepStatusIpcResult = SweepStatusResponse | TurnContextStaleServe | typeof IPC_UNAVAILABLE;

export async function requestSweepStart(
  socketPath: string,
  req: SweepStartClientRequest,
  opts: { timeoutMs?: number } = {},
): Promise<SweepStartIpcResult> {
  const line = JSON.stringify({ kind: 'sweep_start', protocol: 2, ...req } satisfies SweepStartRequest);
  return syncRoundTrip<SweepStartResponse>(socketPath, line, opts.timeoutMs ?? SWEEP_START_CLIENT_TIMEOUT_MS);
}

export async function requestSweepStatus(
  socketPath: string,
  req: SweepStatusClientRequest,
  opts: { timeoutMs?: number } = {},
): Promise<SweepStatusIpcResult> {
  const line = JSON.stringify({ kind: 'sweep_status', protocol: 2, ...req } satisfies SweepStatusRequest);
  return syncRoundTrip<SweepStatusResponse>(socketPath, line, opts.timeoutMs ?? SWEEP_STATUS_CLIENT_TIMEOUT_MS);
}

async function syncRoundTrip<Resp extends { ok: boolean; protocol: 2 }>(
  socketPath: string,
  line: string,
  timeoutMs: number,
): Promise<Resp | TurnContextStaleServe | typeof IPC_UNAVAILABLE> {
  if (Buffer.byteLength(line, 'utf8') + 1 > MAX_MSG_BYTES) return IPC_UNAVAILABLE;
  const resp = await roundTrip(socketPath, line, timeoutMs);
  if (resp === IPC_UNAVAILABLE) return IPC_UNAVAILABLE;
  if (!resp || typeof resp !== 'object') return IPC_UNAVAILABLE;
  if ((resp as { protocol?: unknown }).protocol !== 2) return { degraded: 'stale_serve' };
  return resp as Resp;
}

/** One request line out, one response line back. Fail-soft to IPC_UNAVAILABLE. */
function roundTrip(
  socketPath: string,
  requestLine: string,
  timeoutMs: number,
): Promise<unknown | typeof IPC_UNAVAILABLE> {
  // POSIX fast-path only: a Unix domain socket is a real filesystem entry, so
  // existsSync() lets the common "no server running" case skip a syscall.
  // On win32, Bun binds a plain path as a real AF_UNIX socket (afunix.sys
  // reparse-point file) that Bun's existsSync()/statSync() cannot see, so
  // existsSync() is always false here even while a live server is listening
  // and a real connection would succeed. Gating on it on Windows made every
  // IPC call fail closed unconditionally (verified: a listen()+connect()
  // round trip against the same plain path succeeds on Bun 1.3.14 / Windows
  // 11, while existsSync() on that path returns false throughout). Skip the
  // pre-check there and let the connection-level error/timeout handlers
  // below do the real "no server" detection.
  if (process.platform !== 'win32' && !existsSync(socketPath)) {
    return Promise.resolve(IPC_UNAVAILABLE);
  }
  return new Promise((resolve) => {
    let settled = false;
    let buf = '';
    const finish = (v: unknown | typeof IPC_UNAVAILABLE) => {
      if (settled) return;
      settled = true;
      try { sock.destroy(); } catch { /* noop */ }
      resolve(v);
    };
    const sock = net.createConnection(socketPath);
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => {
      sock.write(requestLine + '\n');
    });
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      if (buf.length > MAX_MSG_BYTES) return finish(IPC_UNAVAILABLE);
      const nl = buf.indexOf('\n');
      if (nl < 0) return;
      try {
        return finish(JSON.parse(buf.slice(0, nl)));
      } catch {
        return finish(IPC_UNAVAILABLE);
      }
    });
    // Any error (ENOENT, ECONNREFUSED, stale socket), timeout, or close before
    // a response → treat as unavailable, fall through the ladder.
    sock.on('timeout', () => finish(IPC_UNAVAILABLE));
    sock.on('error', () => finish(IPC_UNAVAILABLE));
    sock.on('close', () => finish(IPC_UNAVAILABLE));
  });
}

// ── Server ────────────────────────────────────────────────────────────────

/**
 * Server: start an IPC listener on `socketPath`. Under a start lock (atomic
 * mkdir at `<socketPath>.starting`) probes the path for an owner first —
 * unless the probe proves nothing listens, returns null and leaves the socket
 * untouched: a serve that accepts, one too busy to accept within the probe
 * budget, or one whose socket-file heartbeat is fresh, is the IPC provider
 * (#4896). Only a dead owner's leftover entry is cleaned up; then hardens the
 * parent dir to 0700, chmods the socket 0600 BEFORE announcing readiness
 * [S3#6], records the inode it bound (closeResolveIpcServer reaps only that
 * file) and heartbeats the file's mtime every SOCKET_HEARTBEAT_MS. Returns the
 * net.Server (caller shuts it down via closeResolveIpcServer). Errors are
 * swallowed (best-effort feature) — returns null if the socket can't be bound.
 *
 * Two call shapes [ENG-3]:
 *   - legacy positional: (socketPath, resolveHandler, onDelivered?) — v1
 *     callers unchanged.
 *   - handler map: (socketPath, { resolve, turn_context? }, opts?) — v2.
 */
export async function startResolveIpcServer(
  socketPath: string,
  handler: ResolveHandler,
  onDelivered?: (block: PointerBlock, req: ResolveRequest) => void,
): Promise<net.Server | null>;
export async function startResolveIpcServer(
  socketPath: string,
  handlers: IpcHandlers,
  opts?: IpcServerOpts,
): Promise<net.Server | null>;
export async function startResolveIpcServer(
  socketPath: string,
  handlerOrHandlers: ResolveHandler | IpcHandlers,
  onDeliveredOrOpts?: ((block: PointerBlock, req: ResolveRequest) => void) | IpcServerOpts,
): Promise<net.Server | null> {
  const handlers: IpcHandlers =
    typeof handlerOrHandlers === 'function' ? { resolve: handlerOrHandlers } : handlerOrHandlers;
  const opts: IpcServerOpts =
    typeof onDeliveredOrOpts === 'function'
      ? { onDelivered: onDeliveredOrOpts }
      : onDeliveredOrOpts ?? {};

  // [S3#6] Parent dir 0700 (create if missing, tighten if present) so an
  // unrelated local user can't even see the socket / secret names.
  try {
    const dir = dirname(socketPath);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(dir, 0o700);
  } catch { /* best effort */ }

  // Only a provably dead owner is displaced (#4896 — a transient serve used
  // to unlink the long-lived one's socket and take the pathname with it on
  // exit). 'live' AND 'unknown' (probe timed out: a serve whose event loop
  // is busy; or a connect error that describes the prober, not the owner)
  // both defer — this serve runs without IPC rather than risk it.
  //
  // probe → reap → listen runs under a start lock (an atomic mkdir beside the
  // socket path). Without it two serves probing within the same few
  // microseconds both see no owner; the first reaps and binds, the second
  // unlink displaces the first's LIVE socket — the #4896 steal re-created by
  // a race — and the first could record the second's inode as its own. The
  // second starter now sees the lock and returns null, exactly as it would
  // for a live owner. A lock whose recorded owner has died is reclaimed at
  // once; one whose owner is alive only past START_LOCK_STALE_MS.
  const lock = acquireStartLock(socketPath);
  if (!lock) return null;
  let owner: SocketOwner;
  try {
    owner = await probeSocketOwner(socketPath);
  } catch {
    lock.release();
    return null;
  }
  if (owner !== 'dead') {
    lock.release();
    return null;
  }
  // A starter that stalled long enough to be reclaimed from must not act on
  // its stale verdict: the reclaimer may have bound the path since. Not ours
  // to release either.
  if (!lock.held()) return null;
  // Remove the dead owner's socket file so bind() can succeed. NOT gated on
  // existsSync/statSync (#4333): on win32 Bun binds a plain path as a real
  // AF_UNIX socket, which leaves a reparse-point file that Bun's existsSync()/
  // statSync() cannot see while bind() still fails WSAEADDRINUSE against it —
  // unlink is the only fs call that observes the entry. ENOENT and EISDIR/
  // EPERM (a directory we must not touch) are swallowed.
  try { unlinkSync(socketPath); } catch { /* nothing stale, or not ours to remove */ }
  // The lock stays held through listen() and the inode snapshot below, so no
  // concurrent starter can slip between our listen() and our stat(); the
  // listen callback and the listen error handler release it.

  return new Promise((resolve) => {
    const server = net.createServer((conn) => {
      let buf = '';
      // One request per connection: once a line is being handled, later data
      // events are ignored. Without this, bytes arriving after the newline
      // while the async handler is mid-await would re-find the SAME first
      // line and process it concurrently — duplicate handler work, duplicate
      // response writes, and duplicated delivery-point event logging.
      let handled = false;
      conn.setEncoding('utf8');
      conn.on('data', async (chunk: string) => {
        if (handled) return;
        buf += chunk;
        if (buf.length > MAX_MSG_BYTES) { conn.destroy(); return; }
        const nl = buf.indexOf('\n');
        if (nl < 0) return;
        handled = true;
        const line = buf.slice(0, nl);
        let resp: string;
        let delivered: { block: PointerBlock; req: ResolveRequest } | null = null;
        let deliveredTurnContext: { result: TurnContextResult; req: TurnContextRequest } | null = null;
        try {
          const parsed = JSON.parse(line) as IpcRequest;
          const kind = (parsed as { kind?: unknown }).kind ?? 'resolve';
          if (kind === 'resolve') {
            const req = parsed as ResolveRequest;
            // [CX2-10] Same source binding as turn_context: a bound server
            // serves ITS registered source only — a resolve request naming a
            // different source is rejected, never re-routed. Unbound servers
            // (legacy positional callers) keep the v1 pass-through behavior.
            if (req.sourceId && opts.boundSourceId && req.sourceId !== opts.boundSourceId) {
              resp = JSON.stringify({ ok: false, error: 'source_mismatch' } satisfies ResolveResponse);
            } else {
              const block = await handlers.resolve(req);
              const out: ResolveResponse = { ok: true, block };
              resp = JSON.stringify(out);
              if (block) delivered = { block, req };
            }
          } else if (kind === 'turn_context') {
            const req = parsed as TurnContextRequest;
            const tcResp = await handleTurnContext(req, handlers, opts);
            resp = JSON.stringify(tcResp);
            // Feedback-loop seam: only an ok response carrying a non-empty
            // block counts as a candidate delivery (rejections, degraded-null
            // and empty blocks injected nothing).
            if (tcResp.ok && tcResp.block && tcResp.block.text) {
              deliveredTurnContext = { result: tcResp.block, req };
            }
          } else if (kind === 'context_pack') {
            resp = JSON.stringify(
              await handleContextPack(parsed as ContextPackRequest, handlers, opts),
            );
          } else if (kind === 'sync_start') {
            resp = JSON.stringify(
              await handleSyncKind(parsed as SyncStartRequest, handlers.sync_start, opts),
            );
          } else if (kind === 'sync_status') {
            resp = JSON.stringify(
              await handleSyncKind(parsed as SyncStatusRequest, handlers.sync_status, opts),
            );
          } else if (kind === 'sync_abort') {
            resp = JSON.stringify(
              await handleSyncKind(parsed as SyncAbortRequest, handlers.sync_abort, opts),
            );
          } else if (kind === 'sweep_start') {
            resp = JSON.stringify(
              await handleSyncKind(parsed as SweepStartRequest, handlers.sweep_start, opts),
            );
          } else if (kind === 'sweep_status') {
            resp = JSON.stringify(
              await handleSyncKind(parsed as SweepStatusRequest, handlers.sweep_status, opts),
            );
          } else {
            resp = JSON.stringify({ ok: false, error: `unknown_kind:${String(kind)}` });
          }
        } catch (e) {
          resp = JSON.stringify({ ok: false, error: (e as Error).message });
        }
        try {
          conn.write(resp + '\n');
          // Write accepted — the client (250ms budget) may still have hung
          // up, but this is the closest observable delivery point.
          if (delivered && opts.onDelivered) {
            try { opts.onDelivered(delivered.block, delivered.req); } catch { /* telemetry only */ }
          }
          if (deliveredTurnContext && opts.onTurnContextDelivered) {
            try { opts.onTurnContextDelivered(deliveredTurnContext.result, deliveredTurnContext.req); } catch { /* telemetry only */ }
          }
        } catch { /* client gone — do NOT log undelivered pointers */ }
        conn.end();
      });
      conn.on('error', () => { try { conn.destroy(); } catch { /* noop */ } });
    });
    server.on('error', (e: NodeJS.ErrnoException) => {
      if (process.env.GBRAIN_DEBUG === '1') {
        process.stderr.write(`[resolve-ipc] listen failed (${e.code ?? 'unknown'}) at ${socketPath}\n`);
      }
      // EADDRINUSE here is losing a concurrent election: whoever bound is the
      // provider. Either way the start lock is ours to give back.
      lock.release();
      resolve(null);
    });
    server.listen(socketPath, () => {
      // Mode set BEFORE readiness is announced (the resolve() below) [S3#6].
      try { chmodSync(socketPath, 0o600); } catch { /* best effort */ }
      // Remember the inode of the file THIS server created, so the owner's
      // shutdown can tell its own socket from one another serve has since put
      // at the same path (closeResolveIpcServer / unlinkSocketIfOwned).
      // Unknown inode → the close path leaves the file alone; the next
      // starter's probe reaps a truly stale one. Taken while the start lock
      // is still held, so it is ours.
      let ino: number | undefined;
      try {
        ino = statSync(socketPath).ino;
        (server as OwnedSocketServer)[OWNED_SOCKET_INODE] = ino;
      } catch { /* best effort */ }
      // Owner record: `<socket>.owner` = { pid, ino }. Independent liveness
      // evidence for probers — a pid does not share our event loop, so a
      // stalled owner stays live and a crashed one is reaped at once
      // (classifyRefusedProbe). Written only when we know which inode is ours.
      if (ino !== undefined) writeOwnerSidecar(socketPath, ino);
      // Owner heartbeat: keep the socket file's mtime fresh so a prober whose
      // connect was refused can tell a BUSY owner from a dead leftover
      // (classifyRefusedProbe). connect()/accept() never touch a unix
      // socket's inode times, so the mtime is ours alone. Touch only while
      // the path is still ours — a displaced listener must never freshen the
      // newcomer's file.
      const hbMs = opts.heartbeatMs ?? SOCKET_HEARTBEAT_MS;
      const hb = setInterval(() => {
        if (!ownsSocketPath(socketPath, server)) { clearInterval(hb); return; }
        const now = new Date();
        try { utimesSync(socketPath, now, now); } catch { /* best effort */ }
      }, hbMs);
      hb.unref?.();
      (server as OwnedSocketServer)[SOCKET_HEARTBEAT] = hb;
      server.on('close', () => clearInterval(hb));
      lock.release();
      resolve(server);
    });
  });
}

/** Owner heartbeat period: the listener touches its socket file this often. */
export const SOCKET_HEARTBEAT_MS = 5_000;
/**
 * A refused probe on a socket file touched more recently than this is a BUSY
 * owner, not a dead one. Six heartbeats of slack; a crashed owner's file goes
 * stale after this and is reaped by the next starter.
 */
export const SOCKET_HEARTBEAT_STALE_MS = 30_000;

/**
 * A start lock whose recorded owner is ALIVE is reclaimed only past this age
 * (a starter suspended mid-start, or a reused pid) — well past the ~300 ms a
 * start holds it. A lock whose owner pid is gone is reclaimed at once.
 */
export const START_LOCK_STALE_MS = 60_000;

export interface StartLock {
  /** Give the lock back — only if it is still the directory we created. */
  release(): void;
  /** Is the lock directory still the one we created (same inode)? */
  held(): boolean;
}

/**
 * Serialize probe → reap → listen across processes with an atomic mkdir at
 * `<socketPath>.starting`, our pid recorded inside. Returns null when another
 * starter holds the lock (it becomes the provider; this one returns null
 * upstream). A lock whose recorded owner is dead (kill(pid, 0) → ESRCH) is
 * reclaimed immediately; one whose owner is alive or unknown only once older
 * than START_LOCK_STALE_MS. Reclaim is rename-then-remove, so of two
 * reclaimers exactly one proceeds; release is inode-checked, so a starter
 * that was reclaimed from cannot remove the reclaimer's fresh lock.
 */
export function acquireStartLock(socketPath: string): StartLock | null {
  const lockDir = `${socketPath}.starting`;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      mkdirSync(lockDir);
    } catch (e) {
      if ((e as NodeJS.ErrnoException)?.code !== 'EEXIST') return null;
      if (!startLockIsStale(lockDir)) return null;
      // Atomic reclaim: one reclaimer wins the rename; the other's rename
      // fails and its next mkdir meets the winner's fresh lock.
      const tomb = `${lockDir}.reclaimed-${process.pid}-${Date.now()}`;
      try {
        renameSync(lockDir, tomb);
        rmSync(tomb, { recursive: true, force: true });
      } catch { /* someone else reclaimed it first */ }
      continue;
    }
    let ino: number;
    try {
      writeFileSync(join(lockDir, 'owner'), `${process.pid}\n`, { mode: 0o600 });
      ino = statSync(lockDir).ino;
    } catch {
      // A lock we cannot identify is a lock we must not hold: it would block
      // every other starter until reclaimed.
      try { rmSync(lockDir, { recursive: true, force: true }); } catch { /* noop */ }
      return null;
    }
    const held = () => {
      try { return statSync(lockDir).ino === ino; } catch { return false; }
    };
    return {
      held,
      release: () => {
        if (!held()) return;
        try { rmSync(lockDir, { recursive: true, force: true }); } catch { /* already gone */ }
      },
    };
  }
  return null;
}

/** Is `lockDir` a start lock nobody live holds? See acquireStartLock. */
function startLockIsStale(lockDir: string): boolean {
  try {
    const ageMs = Date.now() - statSync(lockDir).mtimeMs;
    const pid = readPidFile(join(lockDir, 'owner'));
    if (pid !== null && processAlive(pid) === false) return true; // owner died mid-start
    return ageMs > START_LOCK_STALE_MS;
  } catch {
    return false; // vanished under us — the caller's next mkdir decides
  }
}

function readPidFile(path: string): number | null {
  try {
    const n = Number.parseInt(readFileSync(path, 'utf8').trim(), 10);
    return Number.isInteger(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

/**
 * Does a process with this pid exist? kill(pid, 0) sends nothing: true when
 * it exists (EPERM counts — it exists, it is just not ours), false on ESRCH,
 * null when the answer cannot be had.
 */
export function processAlive(pid: number): boolean | null {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    if (code === 'ESRCH') return false;
    if (code === 'EPERM') return true;
    return null;
  }
}

/** Sidecar beside the socket naming its owner: `{ pid, ino }` of the listener that bound it. */
export function ownerSidecarPath(socketPath: string): string {
  return `${socketPath}.owner`;
}

function writeOwnerSidecar(socketPath: string, ino: number): void {
  try {
    writeFileSync(ownerSidecarPath(socketPath), `${JSON.stringify({ pid: process.pid, ino })}\n`, { mode: 0o600 });
  } catch { /* best effort — probers fall back to the heartbeat */ }
}

/**
 * Read the owner record. Null when absent, malformed, or — given the socket
 * file's current inode — naming a different inode (a previous owner's record
 * the newcomer has not yet replaced).
 */
export function readOwnerSidecar(socketPath: string, currentIno?: number): { pid: number; ino: number } | null {
  try {
    const raw = JSON.parse(readFileSync(ownerSidecarPath(socketPath), 'utf8')) as { pid?: unknown; ino?: unknown };
    if (typeof raw.pid !== 'number' || typeof raw.ino !== 'number') return null;
    if (currentIno !== undefined && raw.ino !== currentIno) return null;
    return { pid: raw.pid, ino: raw.ino };
  } catch {
    return null;
  }
}

function removeOwnerSidecarIfOurs(socketPath: string, ino: number): void {
  const side = readOwnerSidecar(socketPath);
  if (!side || side.ino !== ino) return; // absent, or a newer owner's — leave it
  try { unlinkSync(ownerSidecarPath(socketPath)); } catch { /* noop */ }
}

/** Property under which `startResolveIpcServer` records the inode it bound. */
const OWNED_SOCKET_INODE = Symbol.for('gbrain.resolveIpc.ownedSocketInode');
/** Property holding the owner heartbeat timer. */
const SOCKET_HEARTBEAT = Symbol.for('gbrain.resolveIpc.socketHeartbeat');
type OwnedSocketServer = net.Server & {
  [OWNED_SOCKET_INODE]?: number;
  [SOCKET_HEARTBEAT]?: ReturnType<typeof setInterval>;
};

/**
 * Does the file currently at `socketPath` have the inode `server` recorded at
 * listen time? False when the path is gone, was replaced by another serve, or
 * ownership was never recorded.
 */
export function ownsSocketPath(socketPath: string, server: net.Server): boolean {
  const owned = (server as OwnedSocketServer)[OWNED_SOCKET_INODE];
  if (owned === undefined) return false;
  try {
    return existsSync(socketPath) && statSync(socketPath).ino === owned;
  } catch {
    return false;
  }
}

/**
 * Unlink `socketPath` only if it is still the file `server` created (same
 * inode as recorded at listen time). Returns true when a file was unlinked.
 * Another serve may have replaced the path since we bound it, and deleting
 * their live socket on our way out is how every exiting serve used to take
 * the provider down (#4896). Unknown ownership (stat failed at bind) → leave
 * the file; a stale leftover is reaped by the next starter's probe.
 */
export function unlinkSocketIfOwned(socketPath: string, server: net.Server): boolean {
  if (!ownsSocketPath(socketPath, server)) return false;
  try {
    unlinkSync(socketPath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Shut a resolve-IPC listener down WITHOUT taking a newer owner's socket with
 * it. Under Bun (measured 1.3.13, macOS) `server.close()` on a unix-socket
 * listener unlinks the PATHNAME, whether or not the file there is still this
 * server's — a displaced listener closing on exit deleted the newcomer's live
 * socket every time. Rule: close (and reap) only while we still own the path;
 * otherwise leave the listener to die with the process — an unnamed socket
 * holds no path and hurts nobody. Returns what happened, for tests/telemetry.
 */
export function closeResolveIpcServer(
  socketPath: string,
  server: net.Server,
): 'closed' | 'left-open-displaced' | 'left-open-unknown' {
  // Stop the heartbeat on every path: a listener we leave open must never keep
  // touching a file at the path (it is either gone or someone else's).
  const hb = (server as OwnedSocketServer)[SOCKET_HEARTBEAT];
  if (hb) clearInterval(hb);
  const owned = (server as OwnedSocketServer)[OWNED_SOCKET_INODE];
  if (owned === undefined) {
    // Windows: Bun's statSync() cannot see the AF_UNIX reparse-point file
    // (#4333), so ownership is never recorded there — plain close, the
    // pre-change behaviour. On POSIX an unknown inode means our stat right
    // after listen() failed; leaving the listener to die with the process is
    // the conservative choice.
    if (process.platform === 'win32') {
      try { server.close(); } catch { /* noop */ }
      return 'closed';
    }
    return 'left-open-unknown';
  }
  if (!ownsSocketPath(socketPath, server)) return 'left-open-displaced';
  try { server.close(); } catch { /* noop */ }
  // Runtimes that do not unlink on close (Node) still need the reap; under Bun
  // the path is already gone and this is a no-op.
  unlinkSocketIfOwned(socketPath, server);
  removeOwnerSidecarIfOurs(socketPath, owned);
  return 'closed';
}

/** turn_context server path: auth [S3#6] → source binding [CX2-10] → budgeted assembly [G11]. */
async function handleTurnContext(
  req: TurnContextRequest,
  handlers: IpcHandlers,
  opts: IpcServerOpts,
): Promise<TurnContextResponse> {
  if (!handlers.turn_context) {
    return { ok: false, protocol: 2, error: 'unsupported_kind' };
  }
  if (req.protocol !== 2) {
    return { ok: false, protocol: 2, error: 'unsupported_protocol' };
  }
  // Fail closed: no configured secret means NO turn_context service, not open service.
  if (!opts.secret || !secretMatches(req.secret, opts.secret)) {
    return { ok: false, protocol: 2, error: 'unauthorized' };
  }
  // [CX2-10] The server serves ITS registered source only. A request naming a
  // different source is an authorization error, not a routing hint.
  if (req.sourceId && opts.boundSourceId && req.sourceId !== opts.boundSourceId) {
    return { ok: false, protocol: 2, error: 'source_mismatch' };
  }
  try {
    const budget = new Promise<'__budget__'>((r) => {
      const t = setTimeout(() => r('__budget__'), TURN_CONTEXT_SERVER_BUDGET_MS);
      t.unref?.();
    });
    const result = await Promise.race([handlers.turn_context(req), budget]);
    if (result === '__budget__') {
      return { ok: true, protocol: 2, block: null, degradedReason: 'server_budget' };
    }
    return {
      ok: true,
      protocol: 2,
      block: result,
      ...(result?.degradedReason ? { degradedReason: result.degradedReason } : {}),
    };
  } catch (e) {
    return { ok: false, protocol: 2, error: (e as Error).message };
  }
}

/**
 * context_pack server path — same ladder as turn_context (auth [S3#6] →
 * source binding [CX2-10] → budgeted work), with a WIDER budget (cards) and
 * partial-pack semantics: the registered handler passes the budget into the
 * assembler as a wall-clock deadline, so the race below is only the backstop
 * for a hung handler, not the primary degrade mechanism (eng 4A).
 */
async function handleContextPack(
  req: ContextPackRequest,
  handlers: IpcHandlers,
  opts: IpcServerOpts,
): Promise<ContextPackResponse> {
  if (!handlers.context_pack) {
    return { ok: false, protocol: 2, error: 'unsupported_kind' };
  }
  if (req.protocol !== 2) {
    return { ok: false, protocol: 2, error: 'unsupported_protocol' };
  }
  if (!opts.secret || !secretMatches(req.secret, opts.secret)) {
    return { ok: false, protocol: 2, error: 'unauthorized' };
  }
  if (req.sourceId && opts.boundSourceId && req.sourceId !== opts.boundSourceId) {
    return { ok: false, protocol: 2, error: 'source_mismatch' };
  }
  try {
    const budget = new Promise<'__budget__'>((r) => {
      const t = setTimeout(() => r('__budget__'), CONTEXT_PACK_SERVER_BUDGET_MS + 200);
      t.unref?.();
    });
    const result = await Promise.race([handlers.context_pack(req), budget]);
    if (result === '__budget__') {
      return { ok: true, protocol: 2, block: null, degradedReason: 'server_budget' };
    }
    return {
      ok: true,
      protocol: 2,
      block: result,
      ...(result?.degradedReason ? { degradedReason: result.degradedReason } : {}),
    };
  } catch (e) {
    return { ok: false, protocol: 2, error: (e as Error).message };
  }
}

/**
 * Shared auth ladder for the delegated-sync kinds — same fail-closed posture
 * as turn_context (handler absent → unsupported_kind; protocol mismatch →
 * unsupported_protocol; missing/wrong secret → unauthorized). No budget race:
 * the handlers are O(1) in-memory operations in serve-sync-runner.ts.
 */
async function handleSyncKind<Req extends { protocol: number; secret: string }, Resp extends { ok: boolean; protocol: 2 }>(
  req: Req,
  handler: ((req: Req) => Resp | Promise<Resp>) | undefined,
  opts: IpcServerOpts,
): Promise<Resp | { ok: false; protocol: 2; error: string }> {
  if (!handler) return { ok: false, protocol: 2, error: 'unsupported_kind' };
  if (req.protocol !== 2) return { ok: false, protocol: 2, error: 'unsupported_protocol' };
  if (!opts.secret || !secretMatches(req.secret, opts.secret)) {
    return { ok: false, protocol: 2, error: 'unauthorized' };
  }
  try {
    return await handler(req);
  } catch (e) {
    return { ok: false, protocol: 2, error: (e as Error).message };
  }
}

/**
 * Is something listening at `socketPath`? The same owner probe the pre-bind
 * check uses: a leftover socket FILE (dead owner) is not a live provider, so
 * callers must use this rather than existsSync() to decide "a serve is
 * here". 'unknown' (probe timed out, or a connect error that describes the
 * prober rather than the owner) counts as live — the conservative reading,
 * identical to the bind path's "never displace on a timeout".
 */
export async function socketHasLiveListener(socketPath: string): Promise<boolean> {
  return (await probeSocketOwner(socketPath)) !== 'dead';
}

/**
 * Who owns `socketPath`? 'live' — something accepted the connect (a serve),
 * OR the connect was refused while the socket file's owner heartbeat is
 * fresh (a live serve too busy to accept — see classifyRefusedProbe).
 * 'dead' — the connect was hard-refused (ENOENT / ECONNREFUSED / ENOTSOCK)
 * and no fresh heartbeat vouches for an owner: the entry is a dead owner's
 * leftover the caller may remove. 'unknown' — the CLIENT_TIMEOUT_MS budget
 * lapsed with the connect neither accepted nor refused, or the error (EMFILE,
 * EACCES, …) says nothing about the owner. The caller must never clean up on
 * 'unknown': a timeout read as "dead" let a transient serve displace a
 * long-lived one, the very #4896 symptom. The server side tolerates the
 * data-less probe: one-request-per-connection means a connection that closes
 * before its first line is just destroyed.
 */
export type SocketOwner = 'live' | 'dead' | 'unknown';
export async function probeSocketOwner(socketPath: string): Promise<SocketOwner> {
  let code: string | undefined;
  const raw = await new Promise<SocketOwner>((resolve) => {
    let settled = false;
    const probe = new net.Socket();
    const finish = (owner: SocketOwner) => {
      if (settled) return;
      settled = true;
      try { probe.destroy(); } catch { /* noop */ }
      resolve(owner);
    };
    // Listeners BEFORE connect(): under `bun test` Bun can emit the ENOENT
    // for an absent path synchronously inside connect(), which would be an
    // unhandled 'error' if attached afterwards. The code is captured by the
    // first 'error' listener so the refusal can be classified below; the
    // 'dead' the second one settles is the RAW verdict, not the final one.
    probe.once('error', (e: NodeJS.ErrnoException) => { code = e?.code; });
    probe.once('connect', () => finish('live'));
    probe.once('error', () => finish('dead'));
    probe.once('timeout', () => finish('unknown'));
    probe.setTimeout(CLIENT_TIMEOUT_MS);
    try { probe.connect(socketPath); } catch { finish('dead'); }
  });
  if (raw !== 'dead') return raw;
  return classifyRefusedProbe(code, probeFileInfo(socketPath));
}

/** What the filesystem says about the path when a probe connect fails. */
export interface ProbeFileInfo {
  exists: boolean;
  isSocket: boolean;
  /** Age of the file's mtime in ms (the owner heartbeat), null when absent. */
  mtimeAgeMs: number | null;
  /**
   * Owner record verdict: true — the recorded owner pid exists; false — it is
   * gone (ESRCH); null — no usable record (absent, malformed, naming another
   * inode, or kill(pid, 0) could not tell).
   */
  ownerAlive: boolean | null;
}

export function probeFileInfo(socketPath: string): ProbeFileInfo {
  try {
    const st = statSync(socketPath);
    const isSocket = st.isSocket();
    const side = isSocket ? readOwnerSidecar(socketPath, st.ino) : null;
    return {
      exists: true,
      isSocket,
      mtimeAgeMs: Date.now() - st.mtimeMs,
      ownerAlive: side ? processAlive(side.pid) : null,
    };
  } catch {
    return { exists: false, isSocket: false, mtimeAgeMs: null, ownerAlive: null };
  }
}

/**
 * An owner whose process is alive but whose heartbeat is older than this is
 * treated as gone anyway: a stall this long, or a reused pid behind a dead
 * owner's record. Bounds how long a leftover can hold the path hostage.
 */
export const OWNER_STALL_LIMIT_MS = 300_000;

/**
 * Classify a probe connect that did NOT succeed. The error code alone cannot:
 * measured on Bun 1.3.13 / macOS, 172 of 300 connects to a LIVE listener whose
 * event loop was stalled for 4 s failed with ENOENT — the same code a regular
 * file (or nothing) at the path produces — so "hard refusal = dead owner"
 * reaps a busy provider. Two signals decide instead, for a SOCKET file:
 *
 * 1. The owner record (`<socket>.owner`, pid + inode), evidence that does not
 *    share the owner's event loop: pid gone → 'dead' at once, however fresh
 *    the file (a crashed provider's replacement binds immediately); pid alive
 *    → 'live' until the heartbeat is OWNER_STALL_LIMIT_MS old.
 * 2. The heartbeat: an mtime younger than `staleMs` → 'live' (an owner too
 *    busy to accept, or one that left no record).
 *
 * Otherwise ENOENT / ECONNREFUSED / ENOTSOCK (and a connect() that threw
 * synchronously, code undefined) prove nothing listens → 'dead'; every other
 * code — EMFILE/ENFILE (our own fd exhaustion), EACCES/EPERM, EAGAIN,
 * ETIMEDOUT, unknown — describes the prober, not the owner → 'unknown'
 * (defer, never reap). The cost of a wrong 'live'/'unknown' is one serve
 * without an IPC binding; the cost of a wrong 'dead' is unlinking the socket
 * every session's hooks depend on.
 */
export function classifyRefusedProbe(
  code: string | undefined,
  info: ProbeFileInfo,
  staleMs: number = SOCKET_HEARTBEAT_STALE_MS,
  ownerStallLimitMs: number = OWNER_STALL_LIMIT_MS,
): SocketOwner {
  if (info.exists && info.isSocket) {
    if (info.ownerAlive === false) return 'dead';
    const ageMs = info.mtimeAgeMs ?? Number.POSITIVE_INFINITY;
    if (info.ownerAlive === true && ageMs < ownerStallLimitMs) return 'live';
    if (ageMs < staleMs) return 'live';
  }
  switch (code) {
    case undefined:
    case 'ENOENT':
    case 'ECONNREFUSED':
    case 'ENOTSOCK':
      return 'dead';
    default:
      return 'unknown';
  }
}
