// Toy target: a tiny in-memory "agent server" with a switch to make it either
// SECURE or VULNERABLE, plus the adapter that red-teams it. This is what makes the
// kit runnable with zero setup — `npm test` drives the real attack specs against
// both postures and proves the oracles tell them apart.
//
// It also documents, in the smallest possible code, what each attack class checks
// and what a real adapter has to supply.

import type { Adapter, AttackSpec, GroundTruthRecord } from '../spec.js';
import { makeForge, type Forge } from '../forge.js';
import { expectAllOk, expectAllRejected, expectStatusIn, expectThrottled, is } from '../oracle.js';

export interface MockOptions {
	/** When false, every guard is disabled — the vulnerable posture. */
	secure: boolean;
	/** Secret the mock server signs and verifies with (also handed to the forge). */
	secret: string;
	/** Requests allowed before the throttle engages (secure posture only). */
	rateLimit?: number;
}

interface DecodedToken {
	header: Record<string, unknown>;
	payload: Record<string, unknown>;
	signatureValid: boolean;
}

/**
 * A deliberately small stand-in for a real API. No network — call `request`
 * directly. The `secure` flag flips every check at once so one instance is the
 * "fixed" server and another is the "vulnerable" one.
 */
export class MockAgentServer {
	private readonly secure: boolean;
	private readonly secret: string;
	private readonly rateLimit: number;
	private hits = 0;
	// Two isolated users' private data, keyed by owner id.
	private readonly workouts: Record<string, { id: string; owner: string }> = {
		'wk-A': { id: 'wk-A', owner: 'user-A' },
		'wk-B': { id: 'wk-B', owner: 'user-B' },
	};

	constructor(opts: MockOptions) {
		this.secure = opts.secure;
		this.secret = opts.secret;
		this.rateLimit = opts.rateLimit ?? 5;
	}

	/** Verify a bearer token the way a correct server would (in secure mode). */
	private verify(token: string | undefined): DecodedToken | null {
		if (!token) return null;
		const parts = token.split('.');
		if (parts.length !== 3) return null;
		let header: Record<string, unknown>;
		let payload: Record<string, unknown>;
		try {
			header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
			payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
		} catch {
			return null;
		}
		// The crux of the forgery attacks: a correct server PINS the algorithm to
		// HS256 and rejects alg:none and any-other-alg tokens, even ones carrying a
		// real-secret signature. The vulnerable server skips this and trusts the
		// header's own claim about how it should be checked.
		const alg = header['alg'];
		if (this.secure) {
			if (alg !== 'HS256') return null; // pin: reject HS384, alg:none, everything else
			if (parts[2] === '') return null; // no unsigned tokens
			// (A real server also recomputes the HMAC; the mock treats a present HS256
			// signature segment as valid, which is enough to exercise the oracles.)
			return { header, payload, signatureValid: true };
		}
		// Vulnerable: accept whatever the token claims, however it is signed.
		return { header, payload, signatureValid: true };
	}

	request(method: string, path: string, opts: { token?: string } = {}): { status: number } {
		// Cost-burst: only the secure server throttles.
		if (path === '/api/chat') {
			this.hits += 1;
			if (this.secure && this.hits > this.rateLimit) return { status: 429 };
			return { status: 200 };
		}

		const decoded = this.verify(opts.token);

		// Admin route: requires a valid token AND role:admin.
		if (path.startsWith('/api/admin/')) {
			if (!decoded) return { status: 401 };
			// Vertical-privilege: a correct server checks the ROLE, not just presence of
			// a token. Vulnerable server serves any authenticated caller.
			if (this.secure && decoded.payload['role'] !== 'admin') return { status: 403 };
			return { status: 200 };
		}

		// Workout read: horizontal isolation — caller may only read their OWN.
		const m = path.match(/^\/api\/workout\/(.+)$/);
		if (m) {
			if (!decoded) return { status: 401 };
			const wk = this.workouts[m[1]];
			if (!wk) return { status: 404 };
			if (this.secure && wk.owner !== decoded.payload['sub']) return { status: 403 };
			return { status: 200 };
		}

		// Share enumeration: a well-formed but unknown id is a clean miss (404); a
		// malformed one is a 400. Either way the guess is denied.
		const s = path.match(/^\/api\/share\/(.+)$/);
		if (s) {
			const id = s[1];
			const wellFormed = /^[0-9a-f]{16}$/.test(id);
			if (!wellFormed) return { status: 400 };
			return { status: 404 }; // no such share — a guess never resolves to someone's data
		}

		return { status: 404 };
	}
}

/** Context the mock adapter wires up for its attacks. */
export interface MockCtx {
	server: MockAgentServer;
	forge: Forge;
	adminEmail: string;
}

/** The attack library, shared by both postures (the server flag is what differs). */
const mockAttacks: AttackSpec<MockCtx>[] = [
	{
		id: 'forgery-alg-none',
		name: 'alg:none admin token',
		cls: 'token-forgery',
		severity: 'critical',
		expected: 'unsigned alg:none token rejected on admin route',
		run: async ({ server, forge, adminEmail }): Promise<GroundTruthRecord[]> => {
			const token = forge.none({ sub: adminEmail, role: 'admin' });
			return [{ label: 'admin+alg:none', status: server.request('GET', '/api/admin/users', { token }).status }];
		},
		oracle: expectAllRejected(),
	},
	{
		id: 'forgery-other-alg',
		name: 'HS384 admin token (real secret)',
		cls: 'token-forgery',
		severity: 'critical',
		expected: 'HS384-signed token rejected — server pins HS256',
		run: async ({ server, forge, adminEmail }): Promise<GroundTruthRecord[]> => {
			const token = forge.alg({ sub: adminEmail, role: 'admin' }, 'HS384');
			return [{ label: 'admin+HS384', status: server.request('GET', '/api/admin/users', { token }).status }];
		},
		oracle: expectAllRejected(),
	},
	{
		id: 'vertical-privilege',
		name: 'authenticated non-admin hits admin route',
		cls: 'vertical-privilege',
		severity: 'high',
		expected: 'valid role:user token rejected on admin route (403)',
		run: async ({ server, forge }): Promise<GroundTruthRecord[]> => {
			const token = forge.hs256({ sub: 'user-A', role: 'user' });
			return [{ label: 'user->admin', status: server.request('GET', '/api/admin/users', { token }).status }];
		},
		oracle: expectAllRejected(),
	},
	{
		id: 'horizontal-isolation',
		name: "read another user's workout",
		cls: 'horizontal-isolation',
		severity: 'high',
		expected: "user-A denied user-B's workout (403)",
		run: async ({ server, forge }): Promise<GroundTruthRecord[]> => {
			const token = forge.hs256({ sub: 'user-A', role: 'user' });
			return [{ label: 'A-reads-B', status: server.request('GET', '/api/workout/wk-B', { token }).status }];
		},
		oracle: expectAllRejected(),
	},
	{
		id: 'unauth-enumeration',
		name: 'guess a share id',
		cls: 'unauth-enumeration',
		severity: 'medium',
		expected: 'guessed share id denied (404 valid-format miss / 400 malformed)',
		run: async ({ server }): Promise<GroundTruthRecord[]> => [
			{ label: 'well-formed-guess', status: server.request('GET', '/api/share/0123456789abcdef').status },
			{ label: 'malformed-guess', status: server.request('GET', '/api/share/not-a-real-id').status },
		],
		oracle: expectStatusIn([400, 404]),
	},
	{
		id: 'cost-burst',
		name: 'unthrottled chat burst',
		cls: 'cost-burst',
		severity: 'medium',
		expected: 'coach burst throttled (≥1 429); all-5xx scores INCONCLUSIVE',
		run: async ({ server }): Promise<GroundTruthRecord[]> =>
			Array.from({ length: 20 }, (_, i) => ({
				label: `turn-${i + 1}`,
				status: server.request('POST', '/api/chat').status,
			})),
		oracle: expectThrottled(),
	},
	// Positive controls: these MUST succeed. A failing control means the harness or
	// environment is wrong — so it is scored apart from the attacks.
	{
		id: 'control-valid-admin',
		name: 'CONTROL: real admin token accepted',
		cls: 'control',
		severity: 'control',
		expected: 'genuine HS256 role:admin token serves admin route (2xx)',
		run: async ({ server, forge, adminEmail }): Promise<GroundTruthRecord[]> => {
			const token = forge.hs256({ sub: adminEmail, role: 'admin' });
			return [{ label: 'valid-admin', status: server.request('GET', '/api/admin/users', { token }).status }];
		},
		oracle: expectAllOk(),
	},
	{
		id: 'control-owner-read',
		name: 'CONTROL: owner reads own workout',
		cls: 'control',
		severity: 'control',
		expected: 'user-A serves user-A workout (2xx)',
		run: async ({ server, forge }): Promise<GroundTruthRecord[]> => {
			const token = forge.hs256({ sub: 'user-A', role: 'user' });
			return [{ label: 'A-reads-A', status: server.request('GET', '/api/workout/wk-A', { token }).status }];
		},
		oracle: expectAllOk(),
	},
];

/**
 * Build a red-team adapter for the toy server in a chosen posture. Pass
 * `secure: true` to see every attack defended, `secure: false` to see the oracles
 * catch the vulnerabilities. This is the reference an author copies to write their
 * own adapter against a real target.
 */
export const mockAdapter = (opts: MockOptions): Adapter<MockCtx> => ({
	name: `mock-agent (${opts.secure ? 'secure' : 'vulnerable'})`,
	setUp: async () => ({
		server: new MockAgentServer(opts),
		forge: makeForge(opts.secret),
		adminEmail: 'admin@example.com',
	}),
	attacks: mockAttacks,
});

// Re-export a predicate the CLI/demo uses for a quick sanity assert.
export { is };
