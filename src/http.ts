// Real HTTP client, injected into an adapter's ctx. Tests inject a mock of the
// same shape, so attack specs never need a live network to be exercised.

export interface HttpResponse {
	status: number;
	body: unknown;
}

export interface HttpOptions {
	token?: string;
	body?: unknown;
	headers?: Record<string, string>;
}

export type HttpClient = (method: string, path: string, opts?: HttpOptions) => Promise<HttpResponse>;

/**
 * @param baseUrl origin of the system under test, e.g. https://staging.example.com
 */
export const makeHttp =
	(baseUrl: string): HttpClient =>
	async (method, path, opts = {}) => {
		const headers: Record<string, string> = { ...(opts.headers ?? {}) };
		if (opts.token) headers['Authorization'] = `Bearer ${opts.token}`;
		if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
		const res = await fetch(`${baseUrl}${path}`, {
			method,
			headers,
			body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
		});
		// A non-JSON body is not an error here — the STATUS is the ground truth, and
		// swallowing a parse failure into `null` keeps a text/plain 404 scoring correctly.
		let body: unknown = null;
		try {
			body = await res.json();
		} catch {
			body = null;
		}
		return { status: res.status, body };
	};
