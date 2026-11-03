"""Checks the live counter API. Adds 1 to the public `total` count per run (plus any rate-limited attempts)."""
import json, sys, urllib.request, urllib.error

API = "https://bench-counter.polished-pine-5c63.workers.dev/v1/counts"
ORIGIN = "https://logoscommander-bench.pages.dev"
ok = fail = 0

def check(name, cond, extra=""):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  {extra}"))

def call(method, url, origin=None, body=None):
    req = urllib.request.Request(url, method=method, data=body, headers={"User-Agent": "logoscommander-test-counter/1.0"})
    if origin:
        req.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()

st, h, b = call("GET", API)
before = json.loads(b)
check("GET 200 with three counts", st == 200 and set(before) == {"total", "blocks", "failures"}, b)
check("CORS allows only the bench origin", h.get("Access-Control-Allow-Origin") == ORIGIN, h)
check("no-store", h.get("Cache-Control") == "no-store")
st, h, _ = call("OPTIONS", API, ORIGIN)
check("OPTIONS 204", st == 204, st)
check("POST from another origin is 403", call("POST", API + "?action=check", "https://evil.example")[0] == 403)
check("POST without Origin is 403", call("POST", API + "?action=check")[0] == 403)
check("unknown action is 400", call("POST", API + "?action=drop", ORIGIN)[0] == 400)
check("other paths are 404", call("GET", API.rsplit("/v1", 1)[0] + "/")[0] == 404)
st, _, b = call("POST", API + "?action=check", ORIGIN, b"DB_PASS=should-be-ignored")
after = json.loads(b)
check("POST check: total +1 (or limited)", st == 200 and (after["total"] == before["total"] + 1 or after.get("limited")), b)
print(f"{ok}/{ok + fail} passed")
sys.exit(1 if fail else 0)
