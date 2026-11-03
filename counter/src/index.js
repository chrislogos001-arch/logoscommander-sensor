// logoscommander-bench counter API: three anonymous counters in D1.
// The handler never reads the request body or any header except Origin and the
// client IP (used only as the rate-limit key, never stored or logged).

const PATH = "/v1/counts";
const ACTIONS = Object.freeze({
  check: ["total"],
  block: ["total", "blocks"],
  fail: ["failures"],
});

function headers(env) {
  return {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

const reply = (env, status, body) => new Response(body === null ? null : JSON.stringify(body), { status, headers: headers(env) });

async function counts(env) {
  const { results } = await env.DB.prepare("SELECT name, n FROM counters").all();
  const c = Object.fromEntries(results.map((r) => [r.name, r.n]));
  return { total: c.total ?? 0, blocks: c.blocks ?? 0, failures: c.failures ?? 0 };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== PATH) return reply(env, 404, { error: "not_found" });
    if (request.method === "OPTIONS") return reply(env, 204, null);
    try {
      if (request.method === "GET") return reply(env, 200, await counts(env));
      if (request.method !== "POST") return reply(env, 405, { error: "method_not_allowed" });

      if (request.headers.get("Origin") !== env.ALLOWED_ORIGIN) return reply(env, 403, { error: "origin_not_allowed" });
      const fields = ACTIONS[url.searchParams.get("action")];
      if (!fields) return reply(env, 400, { error: "unknown_action" });

      // Over the limit: answer 200 with the current counts, so the page does not log an HTTP error.
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const { success } = await env.RL.limit({ key: ip });
      if (!success) return reply(env, 200, { ...(await counts(env)), limited: true });

      const inc = env.DB.prepare("UPDATE counters SET n = n + 1 WHERE name = ?");
      await env.DB.batch(fields.map((f) => inc.bind(f)));
      return reply(env, 200, await counts(env));
    } catch {
      return reply(env, 503, { error: "unavailable" });
    }
  },
};
