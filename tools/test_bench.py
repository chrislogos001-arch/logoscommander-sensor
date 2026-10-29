"""Headless check of dist/: sample run finds the expected rules, redacts the key, and makes no outside requests."""
import functools, http.server, threading, sys
from pathlib import Path
from playwright.sync_api import sync_playwright

DIST = Path(__file__).resolve().parent.parent / "dist"
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(DIST)))
srv.RequestHandlerClass.log_message = lambda *a: None
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{srv.server_address[1]}"
ok = fail = 0

def check(name, cond, extra=""):
    global ok, fail
    ok, fail = (ok + 1, fail) if cond else (ok, fail + 1)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  {extra}"))

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page()
    reqs, errors = [], []
    pg.on("request", lambda r: reqs.append(r.url))
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(base + "/index.html")
    check("version shown", pg.text_content("#ver") == "v1.0.0")
    for tier, action in (("free", None), ("basic", "blocked"), ("cleanup", "purged")):
        pg.click("#sample")
        pg.select_option("#tier", tier)
        pg.click("#run")
        text = pg.text_content("#findings")
        emitted = pg.text_content("#emitted")
        summary = pg.text_content("#summary")
        for rid in ("C01", "P02", "P03", "S03", "X01"):
            check(f"{tier}: {rid} reported", rid in text, text)
        key = "sk" + "_live_4eC39HqLyjWDarjtT1zdp7dc"
        check(f"{tier}: full key never shown in findings", key not in text)
        if tier == "free":
            check("free: output unchanged", emitted == pg.input_value("#outbound"), emitted)
        else:
            check(f"{tier}: key redacted in output", "[REDACTED:S03]" in emitted and key not in emitted, emitted)
            check(f"{tier}: action {action}", action in summary, summary)
    pg.click("#clear")
    pg.fill("#rules", "Always be polite.")
    pg.fill("#outbound", "Hello, how can I help?")
    pg.click("#run")
    check("clean input: no findings", "No conflicts or leaks" in pg.text_content("#summary"))
    check("no requests outside the page origin", all(u.startswith(base) for u in reqs), [u for u in reqs if not u.startswith(base)])
    check("no page errors", not errors, errors)
    b.close()
print(f"{ok}/{ok + fail} passed")
sys.exit(1 if fail else 0)
