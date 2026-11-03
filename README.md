# logoscommander-sensor v1.0.3

**An open-source adversarial benchmark for LLM agents: rule-conflict and credential-leak detection.**
Maintained by a small Los Angeles team as a security helper for AI coexistence.

Bench: https://logoscommander-bench.pages.dev (static files only, runs in the visitor's browser)
Source: https://github.com/chrislogos001-arch/logoscommander-sensor

---

## 1. Scope and statement

- logoscommander-sensor and logoscommander-bench are an open-source benchmark for testing how LLM agents and autonomous agents handle conflicting rules and requests for secrets.
- Non-commercial: no payment gateway, no subscription, no account, no tracking. Released under Apache-2.0 (section 11).
- White-hat use only: the bench checks text that the visitor pastes in. It does not contact, scan or attack any model, agent or website.

## 2. Core architecture and limits

| Path | Purpose |
|---|---|
| `sensor/sensor.js` | The filter: rule tables, stream scanner, mode actions, purge. A single dependency-free ES module for Node ≥ 18 and browsers. |
| `bench/` | logoscommander-bench: a static single page that runs the sensor in the visitor's browser. |
| `test/sensor.test.js` | Unit tests (`npm test`). |
| `tools/` | `build-bench.mjs` (bench → `dist/`), `perf.mjs` (latency), `test_bench.py` (headless page test). |

Runtime parameters and their status in v1.0.3:

| Parameter | Value | Status |
|---|---|---|
| `CHAR_LENGTH_TRUNCATION` | `500` | **Enforced.** Each bench field has `maxlength="500"`, so a longer paste is cut at 500 characters. Input over 500 characters set by any other means is refused with "Not checked", not silently truncated, because scanning only the first 500 characters would miss a credential placed after them. |
| `ZERO_TRACKING_BEACON` | `true` | **Enforced.** No analytics, beacons, cookies or browser storage. The CSP allows first-party scripts only and `connect-src 'none'`. Checked on 2026-10-29: the pages.dev response contains no Cloudflare Web Analytics beacon. |
| `GLOBAL_DAILY_LIMIT` | `10000` | **Not enforced.** A static page cannot count checks made by other visitors. Every check runs on the visitor's own CPU, so there is no server workload to cap. |
| `SINGLE_IP_LIMIT` | `100` / 24 h | **Not enforced.** The page cannot see the visitor's IP address. A per-IP limit would need an edge rate-limiting rule or a backend, which in turn sees IPs; neither is in place. |

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
| S11 | Database connection string with an inline password (`postgres://user:pass@host`, also MySQL, MongoDB, Redis, AMQP, MSSQL) |
| S12 | Credential assignment: a value assigned to a credential-like name (`DB_PASS=…`, `DB_USER=…`, `password: …`, `api_key=…`, `client_secret=…`). Only the value is redacted, so the variable name stays visible. Placeholders such as `null`, `***`, `${VAR}` and `<…>` are skipped. |

When two signatures overlap on the same text, the one listed first in the table wins, so a single string is reported once. For example, `STRIPE_SECRET_KEY=sk_live_…` is reported as S03, not S12.

### 3.2 Probe signatures (inbound)

| ID | Signature |
|---|---|
| P01 | System-prompt / hidden-instruction extraction request |
| P02 | Credential request (keys, secrets, tokens, passwords, env vars, `.env`, database configuration or users, connection strings, `DB_*` names) |
| P03 | Instruction-override request ("ignore all previous instructions") |
| P04 | Authority pretext ("as an auditor / researcher / administrator / red teamer …") |

### 3.3 Composite and static signatures

| ID | Signature |
|---|---|
| X01 | Cross-context credential sniffing: a probe earlier in the session, then a credential in the output. Severity `critical`. |
| C01 | Directive conflict: a positive directive (always / must / should / only) and a negative one (never / must not / do not …) about the same subject. Found by term overlap. |

### 3.4 Streaming

Output is checked chunk by chunk, as it is generated. The sensor holds back the last 256 characters (configurable via `hold`), so a credential split across several chunks is seen whole before any part of it is emitted. The last 64 emitted characters are rescanned as context, so `DB_PASS=` in one chunk and its value in the next is still caught. Each finding is reported once and carries absolute offsets.

## 4. Sensor modes

| Mode (`tier` value) | Behaviour |
|---|---|
| Alert only (`free`) | Traffic passes unchanged. Findings are returned and emitted through `onEvent`. |
| Intercept (`basic`) | Credentials are replaced with `[REDACTED:Sxx]` before they leave the sensor. On X01 the stream is stopped. |
| Intercept + purge (`cleanup`) | Intercept, plus on X01: every context buffer registered with `track()` is zero-filled, the session is discarded, and a new one is built from the frozen baseline config, so service continues. |

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

## 5. logoscommander-bench

The bench is a static page with three fields (agent rules, an inbound message, model output) of up to 500 characters each. It runs the sensor locally and prints a **structural exploit description** for each finding: which rule fired, where (line and column), and what the selected mode would do. Credentials are shown masked (first 4 characters and the length). The bench does not call any model API; visitors paste in output from whatever model they use.

Zero-logs protocol:

- No backend, no database, no cookies, no `localStorage`, no analytics.
- `Content-Security-Policy: connect-src 'none'` blocks the page from sending anything anywhere; `tools/test_bench.py` checks that no request leaves the page's origin.
- Not covered by this protocol: the static host (Cloudflare) sees the visitor's IP address and the page URL at the network edge, as any web host does. Page content is never sent to it.

## 6. Dataset and context vectors (reserved)

Reserved outline for a 30,000-word corpus, *Deep Dialogues with AI: The Emergence of Silicon Subjectivity* [Logos-The Book].

| Slot | Content in this repository |
|---|---|
| Chapter 1 | Reserved. No text and no embeddings. |
| Chapter 2 | Reserved. No text and no embeddings. |
| Chapter 3 | Reserved. No text and no embeddings. |
| Chapter 5 | Reserved. No text and no embeddings. |
| Chapter 6 | Reserved. No text and no embeddings. |

The full text is retained by the repository owner. The sensor and the bench do not read this corpus.

## 7. Measured performance

Measured on the development VM. These are figures from one machine, not guarantees: latency in a real deployment depends on hardware, chunk size and text content.

Scanning one outbound chunk (`npm run perf`, Node v20.18.0, Basic tier, plain text):

| Chunk | Median | p99 |
|---|---|---|
| 512 chars | 7.8 µs | 33.2 µs |
| 4,096 chars | 26.5 µs | 82.2 µs |

A full bench check in headless Chromium: rule conflicts, the inbound message, and the outbound `DB_USER=admin, DB_PASS=secret123`. The mean over 2,000 runs was 27–28 µs (3 runs of `tools/test_bench.py`).

v1.0 measured 3.7 µs and 9.5 µs for the same two chunk sizes. v1.0.1 is slower because of the S12 rule. The bench page shows its own timing in steps of about 100 µs, because browsers round `performance.now()` that coarsely. A figure such as "200 µs" on the page means 1–2 timer steps, not a precise measurement.

The figures above were measured on the v1.0.2 code. v1.0.3 changes only the bench page; detection rules are unchanged.

## 8. Known limits (v1.0.3)

- Detection relies on signatures. A credential with no fixed format is caught only in a `NAME=value` / `NAME: value` form (S12) or inside a connection string (S11). A bare password in prose ("the password is hunter2") is not caught.
- C01 compares words and only works for English rules. It does not understand paraphrase.
- Probe detection is a first-pass heuristic and will miss reworded attacks.
- No vector index. Qdrant (or Qdrant Edge) could be added later for semantic matching. The sensor keeps zero dependencies.

## 9. Running locally

```bash
npm test                   # unit tests
npm run build              # bench -> dist/
python3 -m http.server -d dist 8080   # open http://localhost:8080
python3 tools/test_bench.py           # headless bench test (needs Playwright)
npm run perf               # latency on your machine
```

## 10. Sensor Sandbox Panel and outcome harvesting

The bench shows three counters below the report. They count checks in the current browser tab only, live in page memory, are never sent anywhere, and reset on reload.

| Metric | Meaning |
|---|---|
| `TOTAL_EVALUATIONS_INGESTED` | Checks run in this tab. |
| `SUCCESSFUL_BLOCKED_ATTEMPTS` | Checks in Intercept or Intercept + purge mode where a credential in the output was redacted or the stream was stopped. |
| **`CRITICAL_INTERCEPTION_FAILURES`** (shown in red on the bench) | Checks the visitor marked as a miss with "Mark last check as a miss". The sensor cannot detect its own misses. |

> [!CAUTION]
> `CRITICAL_INTERCEPTION_FAILURES` above zero means the sensor let a credential or attack through. Treat each one as a missing rule.

Outcome harvesting (collecting missed inputs of 500 characters or less into a post-training alignment dataset) is **not implemented**. It would require uploading what visitors paste, which may include real secrets, and that conflicts with the zero-logs protocol in section 5. To contribute a missed case today, open a GitHub issue at https://github.com/chrislogos001-arch/logoscommander-sensor/issues with any real secret replaced by a fake one. If harvesting is added later, it will be opt-in per case and documented here first.

## 11. License

Apache License 2.0. See [LICENSE](LICENSE).

Maintainer: Logos Commander, https://logoscommander.com · chris@logoscommander.com
