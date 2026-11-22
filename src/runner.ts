import type { Adapter, AttackSpec, Result } from './spec.js';

/**
 * Execute attack specs against a wired ctx, apply each oracle, collect scored
 * results. **Never throws** — an attack that errors mid-run is recorded as an
 * error result so one broken probe cannot abort the campaign. A campaign that
 * dies on its third attack silently stops testing the other twelve.
 */
export const runAttacks = async <Ctx>(attacks: AttackSpec<Ctx>[], ctx: Ctx): Promise<Result[]> => {
	const results: Result[] = [];
	for (const attack of attacks) {
		const base = {
			id: attack.id,
			name: attack.name,
			cls: attack.cls,
			severity: attack.severity,
			issue: attack.issue,
			expected: attack.expected,
			...(attack.group ? { group: attack.group } : {}),
			...(attack.requires ? { requires: attack.requires } : {}),
		};
		try {
			const records = await attack.run(ctx);
			const verdict = attack.oracle(records);
			// An oracle may itself signal `error` (inconclusive — e.g. a burst that all-5xx'd
			// so the throttle was never exercised). Propagate it so the report reads ERROR
			// ("investigate"), not FAIL ("vulnerable").
			results.push({ ...base, pass: verdict.pass, detail: verdict.detail, error: verdict.error ?? false });
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			results.push({ ...base, pass: false, detail: `ERROR: ${message}`, error: true });
		}
	}
	return results;
};

/**
 * Run a whole adapter: set up, run its attacks, tear down. Teardown runs even if
 * the campaign throws, so a crashed run does not strand seeded accounts.
 */
export const runAdapter = async <Ctx>(adapter: Adapter<Ctx>): Promise<Result[]> => {
	const ctx = await adapter.setUp();
	try {
		return await runAttacks(adapter.attacks, ctx);
	} finally {
		await adapter.tearDown?.(ctx);
	}
};
