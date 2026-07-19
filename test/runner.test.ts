import { describe, it, expect } from 'vitest';
import { runAttacks } from '../src/runner.js';
import { expectAllRejected } from '../src/oracle.js';
import type { AttackSpec } from '../src/spec.js';

describe('runAttacks', () => {
	it('scores each attack and never aborts on a thrown probe', async () => {
		const attacks: AttackSpec<undefined>[] = [
			{
				id: 'ok',
				name: 'defended',
				cls: 'x',
				severity: 'high',
				expected: 'rejected',
				run: async () => [{ label: 'a', status: 403 }],
				oracle: expectAllRejected(),
			},
			{
				id: 'boom',
				name: 'probe throws',
				cls: 'x',
				severity: 'high',
				expected: 'rejected',
				run: async () => {
					throw new Error('network down');
				},
				oracle: expectAllRejected(),
			},
			{
				id: 'after',
				name: 'still runs after the throw',
				cls: 'x',
				severity: 'high',
				expected: 'rejected',
				run: async () => [{ label: 'a', status: 401 }],
				oracle: expectAllRejected(),
			},
		];

		const results = await runAttacks(attacks, undefined);
		expect(results).toHaveLength(3);
		expect(results[0].pass).toBe(true);
		// The thrown probe is recorded as an ERROR result, not a crash.
		expect(results[1].error).toBe(true);
		expect(results[1].detail).toMatch(/network down/);
		// The campaign continued past the throw.
		expect(results[2].pass).toBe(true);
	});
});
