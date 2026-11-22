// The core vocabulary. Everything else in this package is a function over these
// types, which is why the framework is target-agnostic: nothing here names a
// transport, a provider, or an application.

/** One tool the agent actually EXECUTED, as read from the target's own trace or audit log. */
export interface ToolCall {
	name: string;
	args?: Record<string, unknown>;
}

import type { ReviewEvidence } from './review/target.js';

/** One row of an agent's long-term memory, as read from the store itself. */
export interface MemoryRow {
	content: string;
}

/**
 * One observation of what the system under test ACTUALLY did.
 *
 * `status` is the HTTP status the server returned. `toolCalls` is the tool-call
 * trace for the turn, read out-of-band (an events table, an audit log) and never
 * from the reply; leave it undefined when no trace was read, so an oracle can tell
 * "no tool fired" from "nobody looked". `memoryRows` is the user's long-term memory
 * as it stands in the store after the turn, under the same rule: undefined means
 * nobody read it. `newMemoryRows` is the subset of `memoryRows` that was not there
 * before the attack started; undefined means no before-snapshot was taken. The index
 * signature is deliberate: a target whose ground truth is something else attaches it
 * here, and a custom oracle reads it. What must never appear as the judged field is
 * the agent's own prose.
 */
export interface GroundTruthRecord {
	label: string;
	status: number;
	toolCalls?: ToolCall[];
	memoryRows?: MemoryRow[];
	newMemoryRows?: MemoryRow[];
	/** A code reviewer's verdict on a change: findings and whether it passed. */
	review?: ReviewEvidence;
	[key: string]: unknown;
}

/** An oracle's judgement of one attack's records. */
export interface Verdict {
	pass: boolean;
	detail: string;
	/**
	 * The attack never actually exercised the control (e.g. every request 5xx'd, so
	 * a rate limiter was never reached). Reports as ERROR — "investigate" — never as
	 * FAIL. A harness that cannot tell "not vulnerable" from "not tested" is a
	 * harness that reports false positives.
	 */
	error?: boolean;
}

/** A pure function from observations to a verdict. No I/O, no network, no model. */
export type Oracle = (records: GroundTruthRecord[]) => Verdict;

/**
 * `control` marks a POSITIVE control — a request that must SUCCEED. A failing
 * control means the harness or environment is wrong, not that a vulnerability was
 * found, and the report counts it separately for exactly that reason.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'control';

/**
 * One declarative attack. `run` performs the attempt and returns what the system
 * really did; `oracle` judges those records. The split is the whole design: `run`
 * is allowed to touch the network, `oracle` never is, so every oracle is unit-
 * testable offline against simulated fixed and vulnerable targets.
 *
 * @typeParam Ctx the context type the adapter provides (client, tokens, ids…)
 */
export interface AttackSpec<Ctx = unknown> {
	id: string;
	name: string;
	/** Attack class, e.g. 'token-forgery' | 'vertical-privilege'. Free-form. */
	cls: string;
	severity: Severity;
	/** What defended behavior looks like, in one line — printed in the report. */
	expected: string;
	/** Optional tracking reference (issue URL, ticket id). */
	issue?: string;
	/**
	 * Controls only: the control this trial belongs to. Trials of one control share a
	 * group (e.g. `control-memory-write-1..5` → `control-memory-write`) and the report
	 * scores the group as a pass rate. Defaults to `id`.
	 */
	group?: string;
	/**
	 * Attacks only: the control groups that prove the agent COULD have done what the
	 * attack tries to make it do. A defended verdict counts only when every required
	 * group passes at or above the report's threshold; otherwise the class is
	 * INCONCLUSIVE. (A model that never writes memory "defends" every memory attack.)
	 */
	requires?: string[];
	run: (ctx: Ctx) => Promise<GroundTruthRecord[]>;
	oracle: Oracle;
}

/** A scored attack, ready to format. */
export interface Result {
	id: string;
	name: string;
	cls: string;
	severity: Severity;
	expected: string;
	issue?: string;
	group?: string;
	requires?: string[];
	pass: boolean;
	detail: string;
	error: boolean;
}

/**
 * The ONE interface a target implements. Everything target-specific — how you
 * authenticate, how you seed a throwaway identity, which attacks even apply —
 * lives behind this seam, and nothing behind it leaks into the core.
 */
export interface Adapter<Ctx = unknown> {
	name: string;
	/** Build the wired context: clients, forged tokens, seeded accounts. */
	setUp(): Promise<Ctx>;
	/** Clean up seeded state. Optional — a read-only target needs none. */
	tearDown?(ctx: Ctx): Promise<void>;
	attacks: AttackSpec<Ctx>[];
}
