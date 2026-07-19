import { describe, it, expect } from 'vitest';
import { makeForge, decodeHeader } from '../src/forge.js';

describe('makeForge', () => {
	const forge = makeForge('test-secret');

	it('hs256 produces an HS256-headed token', () => {
		expect(decodeHeader(forge.hs256({ sub: 'a' })).alg).toBe('HS256');
	});

	it('alg produces a token with the requested algorithm', () => {
		expect(decodeHeader(forge.alg({ sub: 'a' }, 'HS384')).alg).toBe('HS384');
	});

	it('none produces an unsigned alg:none token with an empty signature segment', () => {
		const token = forge.none({ sub: 'a', role: 'admin' });
		expect(decodeHeader(token).alg).toBe('none');
		expect(token.split('.')).toHaveLength(3);
		expect(token.split('.')[2]).toBe(''); // no signature
	});
});
