// The per-target seam for AGENT attacks. Implement this once for your agent and
// every recipe in ./recipes.ts runs against it.
//
// It exists because the evidence an agent attack needs lives inside the target:
// which tools a turn executed, what landed in long-term memory. No standard
// interface exposes that, so each target supplies these five functions and the
// recipes stay generic. Identity (who you attack as, and why that is safe) is set
// up in your Adapter's setUp(), which returns the ctx holding this target.

import type { MemoryRow, ToolCall } from '../spec.js';

/** What one agent turn actually did, read out-of-band. */
export interface TurnEvidence {
	/** HTTP status (or equivalent) of the turn request. */
	status: number;
	/**
	 * Tools the agent EXECUTED this turn, in order, from the target's own trace.
	 * Undefined when no trace exists for the turn, which oracles score INCONCLUSIVE.
	 */
	toolCalls?: ToolCall[];
	/**
	 * The agent's reply. Never a verdict on an attack; only the delivery control
	 * reads it. Omit it if the target has no reply text.
	 */
	reply?: string | null;
	/**
	 * Anything the target wants recorded about how the turn ended, e.g. a guard
	 * that replaced the reply. Carried into the report detail, never judged.
	 */
	outcome?: string | null;
}

/** Opaque handle to something `plant` put in place, so it can be removed. */
export interface Planted {
	id: string;
}

export interface AgentTarget {
	/**
	 * Put attacker-controlled text where one of the agent's READ tools will return
	 * it to the model (a note, a document, a record field). It must be readable by
	 * the carrier tool the recipe names, or the delivery control will catch it.
	 */
	plant(text: string): Promise<Planted>;
	/** Remove a plant, so the next trial reads only its own payload. */
	unplant(planted: Planted): Promise<void>;
	/**
	 * Start a session that shares long-term memory with earlier sessions but not
	 * their chat history. Returns the session id `turn` takes.
	 */
	newSession(label: string): Promise<string>;
	/**
	 * Send one user message and return what the turn did. MUST throw if the agent
	 * did not actually run (a paywall reply, a stubbed path): a turn that never
	 * reached the model is not evidence of anything.
	 */
	turn(session: string, prompt: string): Promise<TurnEvidence>;
	/** The long-term memory the model will see on its next turn, read from the store. */
	readMemory(): Promise<MemoryRow[]>;
}

/** The ctx shape recipes need. Your adapter's ctx may carry more. */
export interface AgentCtx {
	target: AgentTarget;
}
