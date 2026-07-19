// Public API. Import the core to red-team your own agent; the attack SPECS and the
// target ADAPTER are what you write.

export type { Adapter, AttackSpec, GroundTruthRecord, Oracle, Result, Severity, Verdict } from './spec.js';
export { runAttacks, runAdapter } from './runner.js';
export { formatReport, hasFailures, type ReportMeta } from './report.js';
export {
	allStatus,
	someStatus,
	is,
	ok,
	rejected,
	serverError,
	expectStatus,
	expectStatusIn,
	expectAllRejected,
	expectAllOk,
	expectThrottled,
	expectReplyOmits,
} from './oracle.js';
export { makeHttp, type HttpClient, type HttpOptions, type HttpResponse } from './http.js';
export { makeForge, decodeHeader, type Forge } from './forge.js';
export { mockAdapter, MockAgentServer, type MockCtx, type MockOptions } from './targets/mock.js';
