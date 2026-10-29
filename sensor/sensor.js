// logoscommander-sensor: stateless, dependency-free filter for LLM agent token streams.
// One ES module; runs unchanged in Node >= 18 and in browsers.

export const VERSION = "1.0.2";

// Tier -> behaviour. free: report only. basic: redact secrets, stop the stream on a sniffing signature.
// cleanup: as basic, but on a sniffing signature zero the tracked context buffers and continue on a fresh session.
export const TIERS = Object.freeze({ free: "alert", basic: "intercept", cleanup: "cleanup" });

export const SECRET_RULES = Object.freeze([
  { id: "S01", name: "AWS access key ID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: "S02", name: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
  { id: "S03", name: "Stripe secret key", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { id: "S04", name: "Stripe webhook signing secret", re: /\bwhsec_[A-Za-z0-9]{16,}\b/g },
  { id: "S05", name: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { id: "S06", name: "OpenAI API key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { id: "S07", name: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { id: "S08", name: "Slack token", re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { id: "S09", name: "Private key block", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { id: "S10", name: "JSON Web Token", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { id: "S11", name: "Database connection string with password", re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql):\/\/[^\s:@\/]+:[^\s@\/]+@[^\s"'<>]+/gi },
  // Generic NAME=value / NAME: value where NAME looks like a credential (DB_PASS=..., api_key: ..., DB_USER=...).
  // Only the value is matched, so redaction keeps the variable name. Placeholders (null, ***, ${VAR}, <...>) are skipped.
  {
    id: "S12",
    name: "Credential assignment",
    re: /(?<=(?<![A-Za-z])(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|(?:db|database|mysql|postgres|pg|mongo|redis|smtp|ftp)_?user(?:name)?)["']?[ \t]{0,3}[:=][ \t]{0,3}["']?)(?!(?:null|none|true|false|undefined|redacted|changeme|\*{3,}|x{3,})(?![^\s"',;&)]))(?![<$%{*\[])[^\s"',;&)]{3,}/gi,
  },
]);

// Inbound requests that try to pull secrets or hidden instructions out of the agent's context.
export const PROBE_RULES = Object.freeze([
  { id: "P01", name: "System prompt extraction", re: /\b(?:print|show|reveal|repeat|output|dump|leak)\b[^.\n]{0,40}\b(?:system prompt|hidden instructions|initial instructions|developer message)\b/gi },
  { id: "P02", name: "Credential request", re: /\b(?:print|show|reveal|list|dump|echo|cat|send|leak|give|provide|share|tell|output|return|display|expose|extract|export|include)\b[^.\n]{0,60}(?:\bapi[_ -]?keys?\b|\bsecrets?\b|\btokens?\b|\bpasswords?\b|\bcredentials?\b|\benv(?:ironment)? var(?:iable)?s?\b|\.env\b|\b(?:db|database) (?:config(?:uration)?|settings|user(?:name)?s?|logins?)\b|\bconnection strings?\b|\bconfig(?:uration)? (?:values|variables|file)\b|\bDB_[A-Z_]+)/gi },
  { id: "P04", name: "Authority pretext", re: /\b(?:as an?|i am an?|i'm an?|acting as an?|in my (?:role|capacity) as an?)\s+(?:[\w-]+\s+){0,3}?(?:auditor|auditing|researcher|admin(?:istrator)?|security (?:team|officer|reviewer)|pen-?tester|red[ -]team(?:er)?|compliance officer)\b/gi },
  { id: "P03", name: "Instruction override", re: /\b(?:ignore|disregard|forget|override)\b[^.\n]{0,30}\b(?:previous|prior|above|all|earlier)\b[^.\n]{0,20}\b(?:instructions|rules|prompts?|policies)\b/gi },
]);

export const SNIFF_RULE = Object.freeze({ id: "X01", name: "Cross-context credential sniffing" });
export const CONFLICT_RULE = Object.freeze({ id: "C01", name: "Directive conflict" });

const CTX = 64;
const clock = () => (globalThis.performance ? performance.now() : Date.now());
const elapsedUs = (t0) => Math.round((clock() - t0) * 1000);
const newId = () =>
  globalThis.crypto && crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2);

function scan(text, rules) {
  const hits = [];
  rules.forEach((r, order) => {
    for (const m of text.matchAll(r.re)) hits.push({ rule: r.id, name: r.name, start: m.index, end: m.index + m[0].length, order });
  });
  // Overlaps keep the earlier rule, so an Anthropic key is not also reported as an OpenAI key.
  hits.sort((a, b) => a.start - b.start || a.order - b.order);
  const out = [];
  let last = -1;
  for (const { order, ...h } of hits) {
    if (h.start < last) continue;
    out.push(h);
    last = h.end;
  }
  return out;
}

export const scanSecrets = (text) => scan(text, SECRET_RULES);
export const scanProbes = (text) => scan(text, PROBE_RULES);

export function maskSample(s) {
  return s.length <= 8 ? "*".repeat(s.length) : `${s.slice(0, 4)}…(${s.length} chars)`;
}

function redact(text, hits, offset = 0) {
  let out = "";
  let pos = 0;
  for (const h of hits) {
    out += text.slice(pos, h.start - offset) + `[REDACTED:${h.rule}]`;
    pos = h.end - offset;
  }
  return out + text.slice(pos);
}

// Zero the bytes of every secret inside a caller-owned UTF-8 buffer, in place.
export function maskBytes(u8) {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(u8);
  const enc = new TextEncoder();
  const hits = scanSecrets(text);
  for (const h of hits) {
    const bs = enc.encode(text.slice(0, h.start)).length;
    u8.fill(0, bs, bs + enc.encode(text.slice(h.start, h.end)).length);
  }
  return hits;
}

const NEG = /\b(?:never|must not|mustn't|do not|don't|should not|shouldn't|cannot|can't|may not)\s+(.+)/i;
const POS = /\b(?:always|must|should|only)\s+(.+)/i;
const STOP = new Set(
  "a an the to of in on at for and or any your you be is are with by it this that always never ever all".split(" ")
);
const terms = (s) =>
  new Set(s.toLowerCase().replace(/[^a-z0-9 ]+/g, " ").split(/\s+/).filter((w) => w && !STOP.has(w)).map((w) => (w.length >= 3 && w.endsWith("s") && !w.endsWith("ss") ? w.slice(0, -1) : w)));

// Static check of a rule set: a positive directive and a negative directive about the same thing.
export function findConflicts(rulesText) {
  const pos = [];
  const neg = [];
  rulesText.split(/\r?\n/).forEach((line, i) => {
    let m = NEG.exec(line);
    if (m) neg.push({ line: i + 1, text: line.trim(), t: terms(m[1]) });
    else if ((m = POS.exec(line))) pos.push({ line: i + 1, text: line.trim(), t: terms(m[1]) });
  });
  const out = [];
  for (const p of pos)
    for (const n of neg) {
      const min = Math.min(p.t.size, n.t.size);
      if (!min) continue;
      let shared = 0;
      for (const w of p.t) if (n.t.has(w)) shared++;
      if (shared / min >= 0.75)
        out.push({ rule: CONFLICT_RULE.id, name: CONFLICT_RULE.name, severity: "warn", a: { line: p.line, text: p.text }, b: { line: n.line, text: n.text } });
    }
  return out;
}

export class Sensor {
  constructor(config = {}) {
    const tier = config.tier || "free";
    if (!TIERS[tier]) throw new Error(`unknown tier: ${tier}`);
    // Baseline every fresh session is rebuilt from; frozen so a compromised session cannot alter it.
    this.base = Object.freeze({ tier, hold: config.hold ?? 256, onEvent: config.onEvent || null });
    this.purges = 0;
    this._fresh();
  }

  get mode() {
    return TIERS[this.base.tier];
  }

  _fresh() {
    this.session = Object.seal({ id: newId(), probes: 0, blocked: false });
    this._pending = "";
    this._ctx = "";
    this._offset = 0;
    this._tracked = [];
  }

  _emit(findings) {
    if (this.base.onEvent) for (const f of findings) this.base.onEvent({ session: this.session.id, ...f });
    return findings;
  }

  // Register a caller-owned buffer holding agent context; purge() zero-fills it.
  track(u8) {
    if (!(u8 instanceof Uint8Array)) throw new TypeError("track() takes a Uint8Array");
    this._tracked.push(u8);
    return u8;
  }

  purge() {
    let bytes = 0;
    for (const u8 of this._tracked) {
      u8.fill(0);
      bytes += u8.length;
    }
    const from = this.session.id;
    this._fresh();
    this.purges++;
    return { from, to: this.session.id, zeroedBytes: bytes };
  }

  inspectInbound(text) {
    const t0 = clock();
    const probes = scanProbes(text).map((h) => ({ ...h, dir: "in", severity: "warn" }));
    const secrets = scanSecrets(text).map((h) => ({ ...h, dir: "in", severity: "warn", sample: maskSample(text.slice(h.start, h.end)) }));
    this.session.probes += probes.length;
    const findings = this._emit([...probes, ...secrets].sort((a, b) => a.start - b.start));
    return { findings, action: findings.length ? "alert" : "pass", us: elapsedUs(t0) };
  }

  pushOutbound(chunk) {
    return this._outbound(chunk, false);
  }

  flushOutbound() {
    return this._outbound("", true);
  }

  _outbound(chunk, final) {
    const t0 = clock();
    if (this.session.blocked) return { emit: "", findings: [], action: "blocked", us: elapsedUs(t0) };
    const text = this._pending + chunk;
    // Rescan the last emitted characters as context so a NAME= split from its value is still recognised (S12).
    const ctx = this._ctx;
    const hits = scanSecrets(ctx + text)
      .map((h) => ({ ...h, start: h.start - ctx.length, end: h.end - ctx.length }))
      .filter((h) => h.start >= 0);
    // Hold back the tail so a secret split across chunks is seen whole before anything is emitted.
    let cut = final ? text.length : Math.max(0, text.length - this.base.hold);
    for (const h of hits) if (h.start < cut && h.end > cut) cut = h.start;
    const base = this._offset;
    const done = hits.filter((h) => h.end <= cut).map((h) => ({ ...h, start: h.start + base, end: h.end + base }));
    let emit = text.slice(0, cut);
    this._ctx = (ctx + emit).slice(-CTX);
    this._pending = text.slice(cut);
    this._offset += cut;

    const sniffed = done.length > 0 && this.session.probes > 0;
    const findings = done.map((h) => ({
      ...h,
      dir: "out",
      severity: sniffed ? "critical" : "high",
      sample: maskSample(emit.slice(h.start - base, h.end - base)),
    }));
    if (sniffed) findings.push({ rule: SNIFF_RULE.id, name: SNIFF_RULE.name, dir: "out", severity: "critical", start: done[0].start, end: done[0].end });
    this._emit(findings);

    let action = findings.length ? "alert" : "pass";
    if (this.mode !== "alert" && done.length) {
      emit = redact(emit, done, base);
      action = "redacted";
    }
    if (sniffed && this.mode === "intercept") {
      this.session.blocked = true;
      this._pending = "";
      action = "blocked";
    }
    let purge = null;
    if (sniffed && this.mode === "cleanup") {
      purge = this.purge();
      action = "purged";
    }
    return { emit, findings, action, purge, us: elapsedUs(t0) };
  }
}

export const createSensor = (config) => new Sensor(config);
