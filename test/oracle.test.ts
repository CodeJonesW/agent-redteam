import { describe, it, expect } from 'vitest';
import {
	expectAllOk,
	expectAllRejected,
	expectStatus,
	expectStatusIn,
	expectThrottled,
	expectReplyOmits,
} from '../src/oracle.js';
import type { GroundTruthRecord } from '../src/spec.js';

const rec = (label: string, status: number, extra: Record<string, unknown> = {}): GroundTruthRecord => ({ label, status, ...extra });

describe('status oracles', () => {
	it('expectStatus passes only when every record matches', () => {
		expect(expectStatus(403)([rec('a', 403), rec('b', 403)]).pass).toBe(true);
		expect(expectStatus(403)([rec('a', 403), rec('b', 200)]).pass).toBe(false);
	});

	it('expectAllRejected passes on any 4xx/5xx, fails on a 2xx', () => {
		expect(expectAllRejected()([rec('a', 401), rec('b', 404)]).pass).toBe(true);
		expect(expectAllRejected()([rec('a', 401), rec('b', 200)]).pass).toBe(false);
	});

	it('expectAllOk is the inverse — the positive control', () => {
		expect(expectAllOk()([rec('a', 200)]).pass).toBe(true);
		expect(expectAllOk()([rec('a', 403)]).pass).toBe(false);
	});

	it('expectStatusIn accepts a set (400 OR 404 both deny a guess)', () => {
		expect(expectStatusIn([400, 404])([rec('a', 404), rec('b', 400)]).pass).toBe(true);
		expect(expectStatusIn([400, 404])([rec('a', 200)]).pass).toBe(false);
	});
});

describe('expectThrottled — the hard-won inconclusive case', () => {
	it('passes when a 429 appears', () => {
		const v = expectThrottled()([rec('t1', 200), rec('t2', 429)]);
		expect(v.pass).toBe(true);
	});

	it('fails (vulnerable) when a full burst is served 200', () => {
		const v = expectThrottled()([rec('t1', 200), rec('t2', 200), rec('t3', 200)]);
		expect(v.pass).toBe(false);
		expect(v.error).toBeFalsy();
	});

	it('an all-5xx burst is INCONCLUSIVE (error), never a vulnerability verdict', () => {
		const v = expectThrottled()([rec('t1', 500), rec('t2', 502), rec('t3', 500)]);
		expect(v.pass).toBe(false);
		expect(v.error).toBe(true);
		expect(v.detail).toMatch(/INCONCLUSIVE/);
	});
});

describe('expectReplyOmits — the deliberately weak oracle', () => {
	it('passes when no forbidden phrase is present', () => {
		const v = expectReplyOmits([/system prompt/i])([rec('r', 200, { text: 'I can help you train.' })]);
		expect(v.pass).toBe(true);
		expect(v.detail).toMatch(/WEAK/); // it announces its own weakness
	});

	it('fails when a forbidden phrase leaks', () => {
		const v = expectReplyOmits([/system prompt/i])([rec('r', 200, { text: 'Here is my SYSTEM PROMPT: ...' })]);
		expect(v.pass).toBe(false);
	});
});
