# logoscommander-sensor v1.0

**A stateless security helper for LLM agent environments.**
A small Los Angeles team building a security helper for AI coexistence.

Status: v1.0 base framework. The bench is live at https://logoscommander-bench.pages.dev (Cloudflare Pages, static files only). Nothing is offered for sale yet. Pricing and the affiliate program below are planned, not live.

---

## 1. Abstract

Agent deployments stack many instructions together: system prompts, tool policies, team-specific rules, user requests. Two failures follow from that stacking:

1. **Directive conflicts.** Two rules require opposite behaviour ("Always include the account ID" vs "Never include the account ID"). The model resolves the conflict unpredictably.
2. **Context leakage.** A request coaxes the agent into echoing credentials that sit in its context, such as API keys, webhook secrets, or tokens pasted into tools.

logoscommander-sensor is one dependency-free JavaScript module. It sits between an agent and its I/O and checks both. It holds no database, makes no network calls, and keeps no record of traffic.

## 2. Components

| Path | Purpose |
|---|---|
| `sensor/sensor.js` | The filter: rule tables, stream scanner, tier actions, purge. A single ES module for Node ≥ 18 and browsers. |
| `bench/` | logoscommander-bench: a static single page that runs the sensor in the visitor's browser. |
| `test/sensor.test.js` | Unit tests (`npm test`). |
| `tools/` | `build-bench.mjs` (bench → `dist/`), `perf.mjs` (latency), `test_bench.py` (headless page test). |

## 3. Detection specification

### 3.1 Credential signatures (outbound and inbound)

| ID | Signature |
|---|---|
| S01 | AWS access key ID |
| S02 | GitHub token |
| S03 | Stripe secret / restricted key |
| S04 | Stripe webhook signing secret |
| S05 | Anthropic API key |
| S06 | OpenAI API key |
| S07 | Google API key |
| S08 | Slack token |
| S09 | PEM private key block |
| S10 | JSON Web Token |

When two signatures overlap on the same text, the one listed first in the table wins, so a single string is reported once.

### 3.2 Probe signatures (inbound)

| ID | Signature |
|---|---|
| P01 | System-prompt / hidden-instruction extraction request |
| P02 | Credential request (keys, secrets, tokens, passwords, env vars, `.env`) |
| P03 | Instruction-override request ("ignore all previous instructions") |

### 3.3 Composite and static signatures

| ID | Signature |
|---|---|
| X01 | Cross-context credential sniffing: a probe earlier in the session, then a credential in the output. Severity `critical`. |
| C01 | Directive conflict: a positive directive (always / must / should / only) and a negative one (never / must not / do not …) about the same subject. Found by term overlap. |

### 3.4 Streaming

Output is checked chunk by chunk, as it is generated. The sensor holds back the last 256 characters (configurable via `hold`), so a credential split across several chunks is seen whole before any part of it is emitted. Each finding is reported once and carries absolute offsets.

## 4. Action layer (tiers)

| Tier | Price (planned) | Behaviour |
|---|---|---|
| **Sovereign Sensing** | Free, permanent | Alerts only. Traffic passes unchanged and findings are returned or emitted through `onEvent`. |
| **Basic Intercept** | $20 / month | Credentials are replaced with `[REDACTED:Sxx]` before they leave the sensor. On X01 the stream is stopped. |
| **High-Fidelity Cleanup** | $30 / month | Basic Intercept, plus on X01: every context buffer registered with `track()` is zero-filled, the session is discarded, and a new one is built from the frozen baseline config, so service continues. |

What the cleanup action does, exactly:

- **Zeroing:** applies to `Uint8Array` buffers the integrator registers with `track()`, and to the buffer passed to `maskBytes()`. JavaScript strings are immutable and cannot be overwritten; the sensor drops its references to them and the garbage collector frees them later.
- **Fresh session:** a new in-process session object (new ID, no probe history, empty stream buffer). It is not a new container or VM. The baseline config is `Object.freeze`d and cannot be changed by a session.

```js
import { Sensor } from "./sensor/sensor.js";

const sensor = new Sensor({ tier: "cleanup", onEvent: (f) => console.warn(f.rule, f.severity) });
sensor.track(contextBytes);                 // optional: buffers to zero on purge
sensor.inspectInbound(userMessage);         // probes, inbound credentials
for await (const chunk of modelStream) {
  const r = sensor.pushOutbound(chunk);     // r.emit is safe to forward
  send(r.emit);
  if (r.action === "blocked") break;
}
send(sensor.flushOutbound().emit);
```

## 5. logoscommander-bench (free trial page)

The bench is a static page with three fields: agent rules, an inbound message, and model output. It runs the sensor locally and prints a **structural exploit description** for each finding: which rule fired, where (line and column), and what the selected tier would do. Credentials are shown masked (first 4 characters and the length). The bench does not call any model API; visitors paste in output from whatever model they use.

### Zero-logs protocol

- No backend, no database, no cookies, no `localStorage`, no analytics.
- `Content-Security-Policy: connect-src 'none'` blocks the page from sending anything anywhere; `tools/test_bench.py` checks that no request leaves the page's origin.
- Not covered by this protocol: the static host (e.g. Cloudflare) sees the visitor's IP address and the page URL at the network edge, as any web host does. Page content is never sent to it.

## 6. Measured performance

`npm run perf` on the development VM (Node v20.18.0), Basic tier, plain text:

| Chunk | Median | p99 |
|---|---|---|
| 512 chars | 3.7 µs | 19.1 µs |
| 4,096 chars | 9.5 µs | 51.2 µs |

These figures are for scanning only, measured on one machine. Latency in a real deployment depends on hardware, chunk size and text content.

## 7. Known limits (v1.0)

- Detection relies on signatures. Credentials with no fixed format (passwords, custom tokens) are found only if they match S01–S10.
- C01 compares words and only works for English rules. It does not understand paraphrase.
- Probe detection is a first-pass heuristic and will miss reworded attacks.
- No vector index. Qdrant (or Qdrant Edge) could be added later for semantic matching. v1.0 keeps zero dependencies.

## 8. 30% Global Affiliate Program (planned)

Community security auditors and integrators who refer paying customers will earn **30% commission on paid tiers**. Commission duration, payout schedule and eligibility will be published with the program terms before launch. Until then, nothing in this section is an offer or a guarantee.

## 9. Running locally

```bash
npm test                   # unit tests
npm run build              # bench -> dist/
python3 -m http.server -d dist 8080   # open http://localhost:8080
python3 tools/test_bench.py           # headless bench test (needs Playwright)
npm run perf               # latency on your machine
```

## 10. License

Apache License 2.0. See [LICENSE](LICENSE).

Contact: chris@logoscommander.com
