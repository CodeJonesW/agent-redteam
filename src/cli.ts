#!/usr/bin/env node
// Thin CLI over the library. v0.1 ships one runnable adapter — the toy mock — so a
// reader can `npx agent-redteam demo` and watch the oracles discriminate a secure
// server from a vulnerable one with zero setup. Real targets are driven
// programmatically (see the README "write your own adapter" section); wiring a
// generic CLI target loader is a 0.2 concern, not gold-plated here.

import { runAdapter } from './runner.js';
import { formatReport, hasFailures } from './report.js';
import { mockAdapter } from './targets/mock.js';

const usage = `agent-redteam — red-team your own agent; score on the write path, not the reply.

Usage:
  agent-redteam demo [--vulnerable]   Run the built-in toy target (default: secure posture).

The demo needs no secrets and no network. Point the library at a real target from
your own code — see the README.`;

const main = async (): Promise<void> => {
	const args = process.argv.slice(2);
	const cmd = args[0];

	if (!cmd || cmd === '-h' || cmd === '--help') {
		console.log(usage);
		process.exit(0);
	}

	if (cmd === 'demo') {
		const secure = !args.includes('--vulnerable');
		// A fixed demo secret — the mock signs and verifies with it. A real adapter
		// takes its secret from the operator's environment, never a literal.
		const adapter = mockAdapter({ secure, secret: 'demo-secret-not-for-production' });
		const results = await runAdapter(adapter);
		console.log(formatReport(results, { target: adapter.name }));
		process.exit(hasFailures(results) ? 1 : 0);
	}

	console.error(`Unknown command: ${cmd}\n\n${usage}`);
	process.exit(2);
};

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
