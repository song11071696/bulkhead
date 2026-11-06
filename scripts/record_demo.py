"""Record the demo video: headless Chromium drives the dashboard while scenarios replay.

    BULKHEAD_MODE=replay BULKHEAD_DATA=.bulkhead/video bulkhead serve &
    pip install playwright            # uses a system Chromium via CHROMIUM_PATH
    python scripts/record_demo.py     # -> media/raw/*.webm + media/captions.srt

then scripts/encode_demo.sh builds media/bulkhead-demo.mp4 (H.264, 1920x1080, soft English subtitles).
Captions are drawn in the page (burned into the video) and also written as an SRT track.
"""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

from playwright.async_api import async_playwright

BASE = os.environ.get("BULKHEAD_URL", "http://127.0.0.1:8787")
ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "media" / "raw"

SCENES = [
    ("poisoned-readme", 6.4, [
        "Task: fix a failing CSV parser test. Bulkhead records it as the session's only source of authority.",
        "Every shell command is one Clocked Pipeline: Inspect → Protect → Decide. Running the test: allowed.",
        "Every tool result goes through Guard + Protect before the agent reads it. Test output: clean.",
        "The upstream README hides an instruction for AI agents. Guard: 99% injection. Only the flagged passages are cut, and the session is now tainted.",
        "`make sync-fixtures` looks harmless: Inspect: under 1% malicious. Decide, given the taint: 99% it follows the injected instruction → denied.",
        "`curl … | bash`: Inspect flags it at step one and stops the pipeline. Protect and Decide are skipped, so no credits are wasted.",
        "The real fix is a file edit. Protect checks what gets written: nothing sensitive, no objection.",
        "Re-running the tests stays allowed in the tainted session: Decide puts it at 3% follows-injection.",
        "New test output comes back: one unrelated test still fails.",
        "The agent reports “All 12 tests now pass”. Verify: 97% contradicted by the test output → it may not stop yet.",
        "Asked once, the agent corrects its report and mentions the attack. Bulkhead lets it finish.",
    ]),
    ("customer-data", 5.4, [
        "Second session: reproduce a customer's bug from a support ticket.",
        "Protect masks the email, phone, card and address before the agent ever sees them.",
        "A test fixture would commit customer data. Protect's anonymized text replaces it (updatedInput), and the company name the test needs is kept.",
        "A live API key hard-coded into source: denied. Secrets belong in the environment.",
        "A card number inside a URL: denied before the request leaves the machine.",
        "The regression test itself runs normally.",
    ]),
    ("gray-zone", 5.0, [
        "Third session: a performance task that points the agent at a GitHub issue.",
        "The issue nudges AI assistants to run a benchmark that uploads data. Guard: injection, but severity low.",
        "So it is not auto-blocked: following it lands in the uncertainty band and goes to the human (ask).",
        "A local micro-benchmark is allowed.",
        "Read-only git commands are decided locally, at zero credits.",
    ]),
    ("resilience", 6.0, [
        "Failure drill: the Clocked gateway is forced to answer 429 twice.",
        "Retried with backoff under the same Idempotency-Key. The third attempt succeeds.",
        "402 out of credits: no retry loop. Fail mode 'ask' hands the decision to the human instead of guessing.",
    ]),
]

TITLE = """
<div id="titlecard" style="position:fixed;inset:0;z-index:50;background:#1f2a44;color:#fff;display:flex;flex-direction:column;
 align-items:center;justify-content:center;font-family:Inter,system-ui,sans-serif;text-align:center">
 <div style="font-size:84px;font-weight:800;letter-spacing:.01em">Bulkhead</div>
 <div style="font-size:34px;color:#cbd5e1;margin-top:10px">A session-aware firewall for AI coding agents</div>
 <div style="font-size:26px;color:#93c5fd;margin-top:36px;max-width:1300px;line-height:1.5">%s</div>
</div>"""


class Captions:
    def __init__(self):
        self.t0 = time.monotonic()
        self.items = []

    def now(self):
        return time.monotonic() - self.t0

    async def show(self, page, text):
        if self.items and self.items[-1][1] is None:
            self.items[-1][1] = self.now()
        self.items.append([self.now(), None, text])
        await page.evaluate("t => { const c = document.querySelector('#caption'); c.textContent = t; c.hidden = !t; }", text)

    def close(self):
        if self.items and self.items[-1][1] is None:
            self.items[-1][1] = self.now()

    def srt(self) -> str:
        def ts(x):
            h, r = divmod(x, 3600)
            m, s = divmod(r, 60)
            return f"{int(h):02d}:{int(m):02d}:{int(s):02d},{int((s % 1) * 1000):03d}"
        return "\n".join(f"{i + 1}\n{ts(a)} --> {ts(b)}\n{t}\n" for i, (a, b, t) in enumerate(self.items) if t)


async def wait_events(page, n, timeout=40):
    t = time.monotonic()
    while time.monotonic() - t < timeout:
        if await page.evaluate("window.bulkhead.state.events.length") >= n:
            return
        await page.wait_for_timeout(100)


async def main():
    RAW.mkdir(parents=True, exist_ok=True)
    for f in RAW.glob("*.webm"):
        f.unlink()
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH", "/usr/bin/chromium"),
                                          args=["--no-sandbox", "--force-device-scale-factor=1"])
        ctx = await browser.new_context(viewport={"width": 1920, "height": 1080}, record_video_dir=str(RAW),
                                        record_video_size={"width": 1920, "height": 1080})
        page = await ctx.new_page()
        cap = Captions()  # video and caption clocks start together
        await page.goto(BASE)
        await page.wait_for_timeout(1500)
        await page.evaluate("h => document.body.insertAdjacentHTML('beforeend', h)",
                            TITLE % "Claude Code's tool calls, checked by Clocked Guard, Inspect, Protect, Decide, Verify and Pipeline before the agent acts")
        cap.items.append([cap.now(), None, "Bulkhead: a session-aware firewall for AI coding agents, built on Clocked."])
        await page.wait_for_timeout(5500)
        await page.evaluate("document.querySelector('#titlecard').remove()")
        await cap.show(page, "Bulkhead sits in Claude Code's hooks. Each tool call is checked by Clocked before the agent acts on it.")
        await page.wait_for_timeout(5500)

        for name, delay, lines in SCENES:
            r = await page.evaluate(f"fetch('/api/scenarios/{name}/run?delay={delay}', {{method:'POST'}}).then(r => r.json())")
            await page.evaluate("sid => window.bulkhead.select(sid)", r["session_id"])
            for i, line in enumerate(lines):
                await wait_events(page, i + 1)
                await cap.show(page, line)
                if name == "poisoned-readme" and i == 3:
                    await page.wait_for_timeout(2600)
                    await page.locator(".ev.quarantine .tab-s").last.click()
                elif name == "customer-data" and i == 2:
                    await page.wait_for_timeout(2400)
                    await page.locator(".ev.redact .tab-s").last.click()
                elif name == "poisoned-readme" and i == 9:
                    await page.wait_for_timeout(1500)
                    await page.locator(".ev.deny details").last.evaluate("d => d.open = true")
            await page.wait_for_timeout(int(delay * 1000))

        await cap.show(page, "")
        await page.evaluate("h => document.body.insertAdjacentHTML('beforeend', h)", TITLE % (
            "Guard · Inspect · Protect · Decide · Verify · Pipeline: every output changes what the agent does.<br>"
            "Offline tests on recorded responses · Docker · MIT<br><br>github.com/song11071696/bulkhead"))
        cap.items.append([cap.now(), None, "Every Clocked output changes what the agent does. github.com/song11071696/bulkhead"])
        await page.wait_for_timeout(7000)
        cap.close()
        await ctx.close()
        await browser.close()
    (ROOT / "media" / "captions.srt").write_text(cap.srt())
    print("recorded", list(RAW.glob("*.webm")), f"{cap.now():.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
