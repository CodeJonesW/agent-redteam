import { describe, it, expect } from 'vitest';
import { runAdapter } from '../src/runner.js';
import { hasFailures, formatReport } from '../src/report.js';
import { mockAdapter } from '../src/targets/mock.js';
import type { Result } from '../src/spec.js';

const SECRET = 'test-secret';
const byId = (results: Result[]): Record<string, Result> => Object.fromEntries(results.map((r) => [r.id, r]));

// This is the load-bearing test of the whole kit: the SAME attack specs, run
// against a SECURE and a VULNERABLE build of the toy target, must come out all-green
// on the first and catch every hole on the second. If the oracles couldn't tell the
// two apart, the harness would be theater.

describe('mock adapter — secure posture', () => {
	it('defends every attack and passes both controls', async () => {
		const results = await runAdapter(mockAdapter({ secure: true, secret: SECRET, rateLimit: 5 }));
		const attacks = results.filter((r) => r.severity !== 'control');
		const controls = results.filter((r) => r.severity === 'control');

		expect(attacks.every((r) => r.pass && !r.error)).toBe(true);
		expect(controls.every((r) => r.pass)).toBe(true);
		expect(hasFailures(results)).toBe(false);
	});
});

describe('mock adapter — vulnerable posture', () => {
	it('the oracles catch every hole, while the controls stay green', async () => {
		const results = await runAdapter(mockAdapter({ secure: false, secret: SECRET }));
		const r = byId(results);

		// Each attack class is genuinely caught on the vulnerable build.
		expect(r['forgery-alg-none'].pass).toBe(false);
		expect(r['forgery-other-alg'].pass).toBe(false);
		expect(r['vertical-privilege'].pass).toBe(false);
		expect(r['horizontal-isolation'].pass).toBe(false);
		expect(r['cost-burst'].pass).toBe(false);
		expect(r['indirect-injection-tool-call'].pass).toBe(false);
		expect(r['indirect-injection-tool-call'].error).toBe(false);
		// A well-formed share guess still 404s in both postures (there IS no such
		// share) — enumeration isn't the mock's injected hole, so it stays defended.
		expect(r['unauth-enumeration'].pass).toBe(true);

		// Controls must remain green even on the vulnerable server — a legitimate
		// admin and a legitimate owner are still served. If a control flipped, the
		// FAIL verdicts above would be untrustworthy.
		expect(r['control-valid-admin'].pass).toBe(true);
		expect(r['control-owner-read'].pass).toBe(true);
		// The gate must not be "never delete": a delete the user asked for still fires.
		expect(r['control-user-requested-delete'].pass).toBe(true);

		expect(hasFailures(results)).toBe(true);
	});
});

describe('report', () => {
	it('renders a table and a summary line', async () => {
		const results = await runAdapter(mockAdapter({ secure: true, secret: SECRET, rateLimit: 5 }));
		const md = formatReport(results, { target: 'mock' });
		expect(md).toMatch(/# Red-Team Report/);
		expect(md).toMatch(/attacks defended/);
	});
});
