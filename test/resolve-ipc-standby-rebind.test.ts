/**
 * Standby re-election (#4896 follow-up): a serve whose IPC start deferred to a
 * live owner keeps re-probing, and binds the socket once that owner is gone —
 * instead of holding a null binding for its whole life while every hook
 * degrades until some serve happens to start.
 */
import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { BrainEngine } from '../src/core/engine.ts';
import { bindResolveIpcForServe } from '../src/mcp/resolve-ipc-binding.ts';
import {
  resolveSocketPath,
  socketHasLiveListener,
  startResolveIpcServer,
} from '../src/core/context/resolve-ipc.ts';
import { withEnv } from './helpers/with-env.ts';

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'gb-ipc-standby-'));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

const posix = process.platform !== 'win32';

describe('bindResolveIpcForServe standby re-election', () => {
  it.skipIf(!posix)('a serve that deferred to a live owner binds the socket once that owner is gone', async () => {
    const dataDir = join(tmp, 'db');
    mkdirSync(dataDir, { recursive: true });
    mkdirSync(join(tmp, '.gbrain'), { recursive: true });
    writeFileSync(
      join(tmp, '.gbrain', 'config.json'),
      JSON.stringify({ engine: 'pglite', database_path: dataDir }),
    );
    await withEnv({ GBRAIN_HOME: tmp, GBRAIN_DATABASE_URL: undefined, DATABASE_URL: undefined }, async () => {
      const sock = resolveSocketPath(dataDir);
      // A live owner already holds the path.
      const owner = await startResolveIpcServer(sock, async () => null);
      expect(owner).not.toBeNull();
      // Bind-time never touches the engine, so a stub is enough.
      const standby = await bindResolveIpcForServe({} as unknown as BrainEngine, 'default', { rebindIntervalMs: 40 });
      try {
        expect(standby.server).toBeNull();
        expect(standby.socketPath).toBeNull();
        // Still the owner's socket after a few re-probes.
        await new Promise((r) => setTimeout(r, 150));
        expect(standby.server).toBeNull();
        expect(await socketHasLiveListener(sock)).toBe(true);
        // The owner exits cleanly (Bun unlinks the pathname on close).
        await new Promise<void>((r) => owner!.close(() => r()));
        // Within a few intervals the standby has become the provider.
        const deadline = Date.now() + 3_000;
        while (!standby.server && Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, 25));
        }
        expect(standby.server).not.toBeNull();
        expect(standby.socketPath).toBe(sock);
        expect(await socketHasLiveListener(sock)).toBe(true);
      } finally {
        standby.close();
      }
      // Its shutdown reaped its own socket; close() stays idempotent.
      expect(existsSync(sock)).toBe(false);
      standby.close();
    });
  });

  it.skipIf(!posix)('close() before the re-election fires cancels it', async () => {
    const dataDir = join(tmp, 'db');
    mkdirSync(dataDir, { recursive: true });
    mkdirSync(join(tmp, '.gbrain'), { recursive: true });
    writeFileSync(
      join(tmp, '.gbrain', 'config.json'),
      JSON.stringify({ engine: 'pglite', database_path: dataDir }),
    );
    await withEnv({ GBRAIN_HOME: tmp, GBRAIN_DATABASE_URL: undefined, DATABASE_URL: undefined }, async () => {
      const sock = resolveSocketPath(dataDir);
      const owner = await startResolveIpcServer(sock, async () => null);
      expect(owner).not.toBeNull();
      const standby = await bindResolveIpcForServe({} as unknown as BrainEngine, 'default', { rebindIntervalMs: 40 });
      expect(standby.server).toBeNull();
      standby.close();
      await new Promise<void>((r) => owner!.close(() => r()));
      // No listener appears on the freed path from the closed standby.
      await new Promise((r) => setTimeout(r, 200));
      expect(standby.server).toBeNull();
      expect(existsSync(sock)).toBe(false);
    });
  });
});
