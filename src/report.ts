// Report formatting: scored results → a Markdown table + summary. Pure string
// building (no I/O), so it is unit-tested and reusable by the CLI, by CI, or by
// anything that wants the campaign as a document.

import type { Result } from './spec.js';

const verdict = (r: Result): string => (r.error ? 'ERROR' : r.pass ? 'PASS' : 'FAIL');

export interface ReportMeta {
	target?: string;
	when?: string;
}

export const formatReport = (results: Result[], meta: ReportMeta = {}): string => {
	const lines: string[] = [];
	lines.push('# Red-Team Report');
	if (meta.target) lines.push(`Target: \`${meta.target}\``);
	if (meta.when) lines.push(`When: ${meta.when}`);
	lines.push('');
	lines.push('| Attack | Class | Expected | Verdict | Detail |');
	lines.push('|---|---|---|---|---|');
	for (const r of results) {
		lines.push(`| ${r.name} | ${r.cls} | ${r.expected} | ${verdict(r)} | ${r.detail} |`);
	}
	lines.push('');

	// Controls are counted apart on purpose: a failing control means the harness or
	// environment is broken, and every other verdict in the run is then suspect.
	const controls = results.filter((r) => r.severity === 'control');
	const attacks = results.filter((r) => r.severity !== 'control');
	const passed = attacks.filter((r) => r.pass).length;
	const failed = attacks.filter((r) => !r.pass && !r.error).length;
	const errored = results.filter((r) => r.error).length;
	const controlsFailed = controls.filter((r) => !r.pass).length;

	lines.push(
		`Summary: ${passed}/${attacks.length} attacks defended, ${failed} FAILED (vulnerable), ${errored} errored, ` +
			`${controls.length - controlsFailed}/${controls.length} controls green.`,
	);
	if (controlsFailed > 0) {
		lines.push(`> WARNING: ${controlsFailed} control(s) failed — verify the harness/environment before trusting these results.`);
	}
	return lines.join('\n');
};

/**
 * Process exit intent: nonzero when any real attack is vulnerable, anything
 * errored, or a control failed. Inconclusive is treated as failure — a run you
 * cannot interpret must not go green in CI.
 */
export const hasFailures = (results: Result[]): boolean =>
	results.some((r) => r.error) ||
	results.some((r) => r.severity !== 'control' && !r.pass) ||
	results.some((r) => r.severity === 'control' && !r.pass);
