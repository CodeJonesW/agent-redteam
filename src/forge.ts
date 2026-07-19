import jwt from 'jsonwebtoken';

// Local token forging. All forging is done LOCALLY with a secret the OPERATOR
// supplies at runtime — never a secret shipped with this package. These helpers
// build the tokens an attacker would present; the target's own verifier decides
// whether to accept them, and that accept/reject is the oracle for the token-
// forgery attack class.
//
// This is generic JWT construction — public knowledge. What is sensitive is the
// signing secret, and that stays in the operator's environment. Nothing here
// weaponizes anything a reader could not write from the JWT spec in ten minutes;
// the value is having it wired into a scored harness.

const b64url = (obj: unknown): string => Buffer.from(JSON.stringify(obj)).toString('base64url');

export interface Forge {
	/** A genuine HS256 token — the algorithm a correctly-configured server signs with. */
	hs256(payload: object): string;
	/** A token signed with an ARBITRARY algorithm (e.g. 'HS384') using the real secret —
	 *  proves the server pins the algorithm and does not accept any-valid-signature. */
	alg(payload: object, algorithm: jwt.Algorithm): string;
	/** An unsigned `alg:none` token (empty signature segment) — proves the server
	 *  rejects the classic "no signature required" bypass. */
	none(payload: object): string;
}

/** Build the forge helpers bound to one operator-supplied secret. */
export const makeForge = (secret: string): Forge => ({
	hs256: (payload) => jwt.sign(payload as object, secret, { algorithm: 'HS256', expiresIn: '1h' }),
	alg: (payload, algorithm) => jwt.sign(payload as object, secret, { algorithm, expiresIn: '1h' }),
	none: (payload) => `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url(payload)}.`,
});

/** Decode a JWT header WITHOUT verifying — used by tests to assert the forged shape. */
export const decodeHeader = (token: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
