/**
 * Postgres code-edge inserts stay under the postgres.js bind limit. The fake
 * executor carries the real POSTGRES_CAPABILITIES and applies the same
 * client-side check vendored postgres.js does (vendor/postgres/src/connection.js:
 * >= 65534 parameters throws MAX_PARAMETERS_EXCEEDED), so an unbatched insert
 * of a minified bundle's edges fails here exactly as it does in postgres.js.
 */
import { describe, expect, test } from 'bun:test';
import { addCodeEdges } from '../src/core/engine-sql/code-edges.ts';
import { POSTGRES_CAPABILITIES } from '../src/core/engine-sql/dialect-postgres.ts';
import type { SqlExecutor } from '../src/core/engine-sql/executor.ts';
import type { CodeEdgeInput } from '../src/core/types.ts';

const POSTGRES_JS_MAX_PARAMS = 65534;

function postgresLikeExecutor() {
  const statements: { sql: string; params: number }[] = [];
  const exec = {
    dialect: 'postgres',
    capabilities: POSTGRES_CAPABILITIES,
    unsafe: async (sql: string, params: readonly unknown[]) => {
      if (params.length >= POSTGRES_JS_MAX_PARAMS) {
        throw Object.assign(new Error('Max number of parameters (65534) exceeded'), { code: 'MAX_PARAMETERS_EXCEEDED' });
      }
      statements.push({ sql, params: params.length });
      const perRow = sql.includes('code_edges_chunk') ? 7 : 6;
      return { rows: [], affectedRows: params.length / perRow };
    },
  } as unknown as SqlExecutor;
  return { exec, statements };
}

function edges(n: number, resolved: boolean): CodeEdgeInput[] {
  return Array.from({ length: n }, (_, i) => ({
    from_chunk_id: i + 1, to_chunk_id: resolved ? i + 2 : null,
    from_symbol_qualified: `mod.fn${i}`, to_symbol_qualified: `mod.callee${i}`,
    edge_type: 'calls', source_id: 'example-source',
  }));
}

describe('Postgres addCodeEdges stays under the postgres.js bind limit', () => {
  test('a minified-bundle edge set (10,991 unresolved, 65,946 binds unbatched) splits under the limit', async () => {
    const { exec, statements } = postgresLikeExecutor();
    expect(await addCodeEdges(exec, edges(10_991, false))).toBe(10_991);
    expect(statements.length).toBeGreaterThan(1);
    for (const statement of statements) {
      expect(statement.params).toBeLessThan(POSTGRES_JS_MAX_PARAMS);
      expect(statement.sql).toContain('code_edges_symbol');
    }
    expect(statements.reduce((rows, statement) => rows + statement.params / 6, 0)).toBe(10_991);
  });

  test('resolved edges (7 binds per row, 66,500 unbatched) split under the limit', async () => {
    const { exec, statements } = postgresLikeExecutor();
    expect(await addCodeEdges(exec, edges(9_500, true))).toBe(9_500);
    expect(statements.length).toBeGreaterThan(1);
    for (const statement of statements) {
      expect(statement.params).toBeLessThan(POSTGRES_JS_MAX_PARAMS);
      expect(statement.sql).toContain('code_edges_chunk');
    }
    expect(statements.reduce((rows, statement) => rows + statement.params / 7, 0)).toBe(9_500);
  });

  test('small and mixed sets keep one statement per edge shape', async () => {
    const { exec, statements } = postgresLikeExecutor();
    expect(await addCodeEdges(exec, [...edges(3, true), ...edges(4, false)])).toBe(7);
    expect(statements.map(s => s.params)).toEqual([21, 24]);
    expect(await addCodeEdges(exec, [])).toBe(0);
    expect(statements.length).toBe(2);
  });
});
