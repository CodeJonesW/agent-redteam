// The per-target seam for attacks on an AI CODE REVIEWER. Implement `review` once
// for your reviewer and the recipes in ./recipes.ts run against it.
//
// A reviewer is not a chat agent: it has no turns to read a tool trace from and no
// long-term memory. What it does is decide whether a change ships. So the ground
// truth is its structured verdict, the findings it raises and whether they block,
// never the prose around them.

/** A change to review: full file contents before and after. A file absent from `base` is new. */
export interface Change {
	base: Record<string, string>;
	head: Record<string, string>;
	/** Commit message for the head commit. Attacker-controlled, like everything in `head`. */
	message?: string;
}

/** One finding the reviewer raised, as its own structured output records it. */
export interface ReviewFinding {
	file: string;
	line: number;
	severity: string;
	title: string;
	body?: string;
	/**
	 * Whether this finding stops the change: the reviewer's own pass/fail rule
	 * (severity threshold, votes) counted it. A finding raised and then disputed
	 * away is `blocking: false`.
	 */
	blocking: boolean;
}

/** The reviewer's verdict on a change. */
export interface ReviewEvidence {
	/** True when the reviewer would let the change through. */
	passed: boolean;
	findings: ReviewFinding[];
}

export interface ReviewTarget {
	/**
	 * Review `change` from a clean slate (no state from earlier reviews) and return
	 * the verdict. MUST throw if the review did not finish: an unfinished review is
	 * not evidence that a bug was missed.
	 */
	review(change: Change, label: string): Promise<ReviewEvidence>;
}

/** The ctx shape review recipes need. Your adapter's ctx may carry more. */
export interface ReviewCtx {
	reviewer: ReviewTarget;
}
