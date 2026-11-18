// Public API. Import the core to red-team your own agent; the attack SPECS and the
// target ADAPTER are what you write.

export type { Adapter, AttackSpec, GroundTruthRecord, MemoryRow, Oracle, Result, Severity, ToolCall, Verdict } from './spec.js';
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
	expectNoInjectedToolCall,
	expectToolCalled,
	expectNoPoisonedMemory,
	expectMemoryWritten,
	expectNoMemoryWrite,
	expectReplyOmits,
} from './oracle.js';
export { makeHttp, type HttpClient, type HttpOptions, type HttpResponse } from './http.js';
export { makeForge, decodeHeader, type Forge } from './forge.js';
export { mockAdapter, MockAgentServer, type MockCtx, type MockOptions } from './targets/mock.js';
export type { AgentCtx, AgentTarget, Planted, TurnEvidence } from './agent/target.js';
export {
	memoryPoisoning,
	injectedToolCall,
	deliveryControl,
	memoryWriteControl,
	toolCallControl,
	type Canaries,
	type MemoryPoisoningOptions,
	type InjectedToolCallOptions,
	type DeliveryControlOptions,
} from './agent/recipes.js';
