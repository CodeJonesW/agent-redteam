# agent-redteam

Red-team your own AI agent and score on the write path, not the reply.

Replies lie. Status codes don't. That's the whole idea.

An agent will happily tell you it refused, or that it locked the door, or that nothing leaked. But the thing you're testing wrote that sentence, so it gets a vote on its own grade. This kit takes the vote away. You declare an attack, you run it, and you judge it on what the system **actually did** — the HTTP status it returned, the row it wrote, the tool it fired. Never on the prose.

It's a small framework plus one seam. You write the attack specs and a target adapter. The runner, the oracles, the report, and the token forging come from here.

## Install

```sh
npm install agent-redteam
```

## See it work in 10 seconds

No secrets, no network. Run the built-in toy target both ways:

```sh
npx agent-redteam demo              # secure posture — every attack defended
npx agent-redteam demo --vulnerable # same specs, holes wide open
```

The secure run is all green. The vulnerable run catches every hole, and the two positive controls stay green in both. That last part matters. If a legit admin got locked out too, the FAILs would be noise.

## The idea in one loop

Every attack, whatever the target, is the same shape:

```
spec  →  run(target)  →  oracle(ground truth)  →  report
```

The only thing that changes per target is one seam: how you send a request, and how you read ground truth for it. A status code. A DB row. A tool-call trace. Everything else is target-agnostic, so generalizing it is a framework plus a pluggable adapter, not a rewrite.

An oracle is a pure function over records. It never touches the network and it never reads a reply body as the verdict. That's what makes the whole thing unit-testable offline against a fixed and a vulnerable server, which is exactly how the demo proves the oracles discriminate.

## Write your own adapter

An adapter is one object. Here's the shape, against a real HTTP target:

```ts
import {
  makeHttp,
  makeForge,
  runAdapter,
  formatReport,
  hasFailures,
  expectAllRejected,
  expectAllOk,
  type Adapter,
  type AttackSpec,
} from 'agent-redteam';

// Secrets come from YOUR environment at runtime, never from this package.
const http = makeHttp(process.env.TARGET_URL!);
const forge = makeForge(process.env.JWT_SECRET!);

interface Ctx {
  http: typeof http;
  forge: typeof forge;
  adminEmail: string;
}

const attacks: AttackSpec<Ctx>[] = [
  {
    id: 'forgery-alg-none',
    name: 'alg:none admin token',
    cls: 'token-forgery',
    severity: 'critical',
    expected: 'unsigned alg:none token rejected on an admin route',
    run: async ({ http, forge, adminEmail }) => {
      const token = forge.none({ sub: adminEmail, role: 'admin' });
      const res = await http('GET', '/api/admin/users', { token });
      return [{ label: 'admin+alg:none', status: res.status }];
    },
    oracle: expectAllRejected(), // any >=400 is a pass. The status is the truth.
  },
];

const adapter: Adapter<Ctx> = {
  name: 'my-agent (staging)',
  setUp: async () => ({ http, forge, adminEmail: process.env.ADMIN_EMAIL! }),
  attacks,
};

const results = await runAdapter(adapter);
console.log(formatReport(results, { target: adapter.name }));
process.exit(hasFailures(results) ? 1 : 0);
```

That's it. `run` is allowed to hit the network. `oracle` isn't. Keep that line and your verdicts stay honest.

### Ground truth deeper than a status code

Sometimes the status isn't enough. A mutation returns 200 but you want to know a tool actually fired, or a row actually changed. Fetch that signal inside `run` and shape it into the record. A `GroundTruthRecord` is `{ label, status }` plus whatever else you attach:

```ts
run: async ({ http }) => {
  const res = await http('POST', '/api/chat', { body: { message: '...' } });
  const trace = await http('GET', '/api/admin/events?type=tool_call');
  return [{ label: 'chat', status: res.status, toolsFired: readTools(trace.body) }];
},
oracle: (records) => {
  const fired = records[0].toolsFired as string[];
  const leaked = fired.includes('delete_account');
  return { pass: !leaked, detail: leaked ? 'delete_account fired!' : `fired: ${fired.join(', ')}` };
},
```

The record carries the write-path evidence. The oracle reads the record, not the words.

## What's in the box

| Piece | What it does |
|---|---|
| `AttackSpec`, `Adapter` | The vocabulary. An attack and the one seam a target implements. |
| `runAttacks` / `runAdapter` | Run the specs. Never aborts on one thrown probe. Teardown always runs. |
| oracles | `expectAllRejected`, `expectStatus`, `expectStatusIn`, `expectAllOk`, `expectThrottled`, `expectReplyOmits`. Pure, offline-testable. |
| `makeForge` | Local JWT forging — HS256, arbitrary-alg, `alg:none`. Generic construction, your secret. |
| `makeHttp` | A tiny fetch client you inject, so specs don't need a live network in tests. |
| `formatReport` / `hasFailures` | Markdown table, a summary, and a nonzero exit intent for CI. |
| `mockAdapter` | The toy target. Copy it to start your own. |

## Two lessons baked in

A couple of things here look like small details and aren't. Both cost me a real debugging session.

**An all-5xx burst is inconclusive, not safe.** `expectThrottled` looks for a 429. But if every request in the burst 5xx'd, the rate limiter never even got reached. That's not "rate limiting is missing." It's "I couldn't tell." So the oracle flags it `error: true` and it reports as ERROR, investigate — never PASS. A harness that can't tell "not vulnerable" from "not tested" hands you false confidence, which is worse than no harness.

**Controls are counted apart.** A positive control is a request that must *succeed* — a real admin on an admin route, an owner reading their own data. If a control fails, your environment is broken and every other verdict in the run is suspect. The report separates them and warns loudly, so a red run means "vulnerable," not "the staging box was down."

## The reply-text oracle is deliberately weak

`expectReplyOmits` reads the reply and fails if a forbidden phrase shows up. It's here because a few things genuinely only surface in words — a model coughing up its system prompt or its tool schemas. But the model wrote that string. So a pass means "didn't say it this time," never "can't." The oracle announces its own weakness in every verdict. Reach for a status or a trace first. Use this one last.

## Running it for real

The offline tests ride CI on every push. No secret, no network. They drive the real specs against a fixed and a vulnerable toy server and prove the oracles still tell them apart. That half is automatic.

The live half — pointing an adapter at your deployed staging box — is manual and local by design. It needs your signing secret and it spends a little real budget. Run it when security-relevant code moves. On a PR touching auth, roles, admin routes, or rate limiting. After a staging deploy, before you promote. Keep a `--allow-prod`-style guard on anything that could hit production, and keep your secret in your environment, never in the repo.

## The case study

This grew out of red-teaming my own fitness-coach agent, an LLM with real tools and real users. The attack classes here — forged tokens, privilege climbs, cross-account reads, cost bursts — are the ones that actually mattered against it, and each verdict is scored on the server's ground truth, not the coach's reply. I wrote the whole method up as a series on AI-agent security. Start here: [the AI Security Roadmap](https://williamjonescodes.com).

## License

MIT © Will Jones (CodeJonesW)
