/**
 * Postgres addCodeEdges batches below the postgres.js bind ceiling (65,534
 * parameters). A 1.5 MB minified bundle produced ~11k unresolved edges; the
 * single 6-binds-per-row INSERT threw MAX_PARAMETERS_EXCEEDED, so the page's
 * projection never installed. PGLite has batched since #4010; this pins the
 * Postgres engine against a real server. DATABASE_URL-gated per the
 * engine-parity convention.
 */
import { installFixtureChunks } from '../helpers/page-projection.ts';
import { describe, test, expect, beforeAll, afterAll } from 'bun:test';
import { setupDB, teardownDB, hasDatabase } from './helpers.ts';
import type { PostgresEngine } from '../../src/core/postgres-engine.ts';

const skip = !hasDatabase();
const describeIfDB = skip ? describe.skip : describe;

let engine: PostgresEngine;
let chunk: number;

beforeAll(async () => {
  if (skip) return;
  engine = await setupDB();
  await engine.putPage('bundle-example-js', {
    type: 'code', page_kind: 'code',
    title: 'bundle.js (javascript)',
    compiled_truth: 'export function run() { return helper(); }',
    timeline: '',
  });
  await installFixtureChunks(engine, 'bundle-example-js', [{
    chunk_index: 0,
    chunk_text: 'export function run() { return helper(); }',
    chunk_source: 'compiled_truth',
    language: 'javascript',
    symbol_name: 'run',
    symbol_type: 'function',
    symbol_name_qualified: 'run',
  }]);
  chunk = (await engine.getChunks('bundle-example-js'))[0]!.id;
});

afterAll(async () => {
  if (skip) return;
  await teardownDB();
});

describeIfDB('addCodeEdges batching — Postgres', () => {
  test('11,000 unresolved edges (66,000 binds unbatched) insert in full', async () => {
    const edges = Array.from({ length: 11_000 }, (_, i) => ({
      from_chunk_id: chunk, to_chunk_id: null,
      from_symbol_qualified: 'run', to_symbol_qualified: `callee${i}`,
      edge_type: 'calls', edge_metadata: { line: i },
    }));
    expect(await engine.addCodeEdges(edges)).toBe(11_000);
    const [row] = await engine.executeRaw<{ n: number }>(
      'SELECT count(*)::int AS n FROM code_edges_symbol WHERE from_chunk_id = $1', [chunk]);
    expect(row.n).toBe(11_000);
  }, 60_000);
});
