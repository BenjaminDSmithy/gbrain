/**
 * Postgres addCodeEdges stays under the postgres.js bind-parameter ceiling.
 * The fake pool enforces the same client-side check postgres.js applies
 * (connection.js: >= 65534 parameters throws MAX_PARAMETERS_EXCEEDED), so an
 * unbatched insert of a minified bundle's edges fails here exactly as it does
 * in postgres.js.
 */
import { describe, expect, test } from 'bun:test';
import { addCodeEdges } from '../src/core/postgres-engine/code-edges.ts';
import type { CodeEdgeInput } from '../src/core/types.ts';

const POSTGRES_JS_MAX_PARAMS = 65534;

function fakePool() {
  const calls: { query: string; params: number }[] = [];
  const sql = {
    unsafe: async (query: string, params: unknown[]) => {
      if (params.length >= POSTGRES_JS_MAX_PARAMS) {
        throw Object.assign(new Error('Max number of parameters (65534) exceeded'), { code: 'MAX_PARAMETERS_EXCEEDED' });
      }
      calls.push({ query, params: params.length });
      const perRow = query.includes('code_edges_chunk') ? 7 : 6;
      return { count: params.length / perRow };
    },
  };
  return { deps: { sql } as never, calls };
}

function edges(n: number, resolved: boolean): CodeEdgeInput[] {
  return Array.from({ length: n }, (_, i) => ({
    from_chunk_id: i + 1, to_chunk_id: resolved ? i + 2 : null,
    from_symbol_qualified: `mod.fn${i}`, to_symbol_qualified: `mod.callee${i}`,
    edge_type: 'calls', source_id: 'example-source',
  }));
}

describe('Postgres addCodeEdges batching', () => {
  test('a minified-bundle edge set (10,991 unresolved, 65,946 binds unbatched) splits under the limit', async () => {
    const { deps, calls } = fakePool();
    expect(await addCodeEdges(deps, edges(10_991, false))).toBe(10_991);
    expect(calls.length).toBeGreaterThan(1);
    for (const call of calls) {
      expect(call.params).toBeLessThan(POSTGRES_JS_MAX_PARAMS);
      expect(call.query).toContain('code_edges_symbol');
    }
    expect(calls.reduce((rows, call) => rows + call.params / 6, 0)).toBe(10_991);
  });

  test('resolved edges (7 binds per row, 66,500 unbatched) split under the limit', async () => {
    const { deps, calls } = fakePool();
    expect(await addCodeEdges(deps, edges(9_500, true))).toBe(9_500);
    expect(calls.length).toBeGreaterThan(1);
    for (const call of calls) {
      expect(call.params).toBeLessThan(POSTGRES_JS_MAX_PARAMS);
      expect(call.query).toContain('code_edges_chunk');
    }
    expect(calls.reduce((rows, call) => rows + call.params / 7, 0)).toBe(9_500);
  });

  test('small and mixed sets keep one statement per edge shape', async () => {
    const { deps, calls } = fakePool();
    expect(await addCodeEdges(deps, [...edges(3, true), ...edges(4, false)])).toBe(7);
    expect(calls.map(c => c.params)).toEqual([21, 24]);
    expect(await addCodeEdges(deps, [])).toBe(0);
    expect(calls.length).toBe(2);
  });
});
