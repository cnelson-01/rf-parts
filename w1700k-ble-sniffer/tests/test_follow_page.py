#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Follow page tests (FOLLOW.md 4): sink/follow.html served by sink/ble_follow.py's standalone server
over the demo database (tools/make_follow_demo_db.py, built in a temp dir).

    /usr/bin/python3 tests/test_follow_page.py

Without a browser: the page is served, it loads nothing from outside, its script parses under node,
every element id the script looks up exists, and every field of the API the page reads exists in
real responses built from the demo story. With headless Chrome and node >= 22 (global WebSocket, for
the DevTools protocol) also: the page renders the demo story, the controls work (attempt row, zoom,
filters, packet detail, address entry, live polling, an error from the server), nothing from the air
or from a label reaches the DOM as markup, and nothing is wider than a phone. Those are skipped when
either program is missing.

Standard library only; the db and Chrome's profile live in a temp dir; the server uses a free port.
"""
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PAGE = os.path.join(ROOT, "sink", "follow.html")
SERVER = os.path.join(ROOT, "sink", "ble_follow.py")
DEMO = os.path.join(ROOT, "tools", "make_follow_demo_db.py")
PY = sys.executable
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
CHROME_PATHS = ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/bin/google-chrome",
                "/usr/bin/chromium", "/usr/bin/chromium-browser")
NODE_PATHS = ("/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node")

PHONE, LOCK, BEACON = "5A:66:77:88:99:AA", "C8:11:22:33:44:55", "D0:AA:BB:CC:DD:01"
SCAN1, GHOST = "4B:10:00:00:00:01", "C0:FF:EE:00:00:01"
HOSTILE = '<img src=x onerror="window.__xss=1">"\'&<b>'

TMP = None
DB = None
T = None          # the demo story ends here
SRV = None        # (process, base url)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _which(paths, name):
    for p in paths:
        if os.path.exists(p):
            return p
    return shutil.which(name)


def setUpModule():
    global TMP, DB, T, SRV
    TMP = tempfile.mkdtemp(prefix="w1700k-follow-page-")
    DB = os.path.join(TMP, "demo.db")
    T = float(int(time.time()))                      # now: the live window shows the story too
    subprocess.run([PY, DEMO, "--db", DB, "--now", repr(T)], check=True, env=ENV,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # a name from the air that is markup: the page must show it as text
    conn = sqlite3.connect(DB)
    conn.execute("UPDATE ble_devices SET name = ? WHERE addr = ?", (HOSTILE, BEACON))
    conn.execute("UPDATE ble_packets SET name = ? WHERE addr = ? AND name IS NOT NULL", (HOSTILE, BEACON))
    conn.commit()
    conn.close()
    port = _free_port()
    proc = subprocess.Popen([PY, SERVER, "--db", DB, "--port", str(port)], env=ENV,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = "http://127.0.0.1:%d" % port
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/healthz", timeout=1).read()
            break
        except Exception:
            time.sleep(0.05)
    SRV = (proc, base)


def tearDownModule():
    if SRV:
        SRV[0].terminate()
        try:
            SRV[0].wait(5)
        except subprocess.TimeoutExpired:
            SRV[0].kill()
    shutil.rmtree(TMP, ignore_errors=True)


def get(path):
    with urllib.request.urlopen(SRV[1] + path, timeout=60) as r:
        return r.status, r.headers, r.read()


def api(path):
    return json.loads(get(path)[2].decode())


def window(addrs, start=None, end=None, extra=""):
    start = T - 600 if start is None else start
    end = T if end is None else end
    return "/api/follow?addrs=%s&start=%r&end=%r&limit=20000%s" % (",".join(addrs), start, end, extra)


def page_script():
    with open(PAGE, encoding="utf-8") as f:
        html = f.read()
    return html, "\n".join(re.findall(r"<script>(.*?)</script>", html, re.S))


# ---- without a browser ---------------------------------------------------------------------------

class PageStaticTest(unittest.TestCase):
    def test_served_from_disk(self):
        status, headers, body = get("/follow?addrs=%s" % LOCK)
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        with open(PAGE, "rb") as f:
            self.assertEqual(body, f.read())

    def test_self_contained(self):
        with open(PAGE, encoding="utf-8") as f:
            html = f.read()
        self.assertNotRegex(html, r"https?://", "no absolute URL: the page must not load anything from outside")
        self.assertNotRegex(html, r"""(?i)(src|href)\s*=\s*["']?//""", "no protocol-relative URL")
        self.assertNotRegex(html, r"(?i)<script[^>]+src=", "scripts are inline")
        self.assertNotRegex(html, r"(?i)<link[^>]+stylesheet", "styles are inline")
        css = "\n".join(re.findall(r"<style>(.*?)</style>", html, re.S))
        self.assertTrue(css)
        self.assertNotRegex(css, r"(?i)@import|url\(\s*['\"]?(?!data:)", "no CSS import / external url()")
        self.assertIn('rel="icon" href="data:', html, "an inline icon: no /favicon.ico request")
        for path in re.findall(r"""fetch\(\s*["'`]([^"'`?]+)""", html):
            self.assertTrue(path.startswith("/api/follow"), path)

    def test_script_parses_under_node(self):
        node = _which(NODE_PATHS, "node")
        if not node:
            self.skipTest("node not installed")
        _, js = page_script()
        f = os.path.join(TMP, "follow-page.js")
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(js)
        r = subprocess.run([node, "--check", f], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_every_id_the_script_uses_exists(self):
        html, js = page_script()
        ids = set(re.findall(r'\bid="([^"]+)"', html))
        used = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', js))
        self.assertTrue(used)
        self.assertEqual(sorted(used - ids), [])

    def test_air_strings_are_escaped_where_built(self):
        _, js = page_script()
        # the few innerHTML writes that do not go through esc() build only from constants
        self.assertIn("function esc(", js)
        for m in re.finditer(r"\.innerHTML\s*=\s*([^;]+);", js):
            rhs = m.group(1)
            for name in ("e.info", "d.name", "f.text", "e.type", ".outcome_detail", "body.error"):
                if name in rhs:
                    self.assertTrue(re.search(r"esc\(", rhs), "innerHTML with %s must escape it" % name)


# Every API field the page reads (path into the response; "[]" walks a list). Each leaf must appear
# in the page's source and in at least one response built from the demo story.
FIELDS = """
start end others events_total events_truncated latest
capabilities.rx_addr capabilities.direction capabilities.reply_undecoded capabilities.bad_crc capabilities.context_truncated
devices[].addr devices[].name devices[].vendor devices[].addr_type devices[].roles devices[].packets_window devices[].rssi_avg devices[].last_seen
adv[].addr adv[].count adv[].by_channel adv[].interval_ms adv[].heard_fraction adv[].connectable
adv[].gaps[].start adv[].gaps[].end adv[].gaps[].open adv[].gaps[].duration_s adv[].gaps[].chance adv[].gaps[].loss adv[].gaps[].attempt
pairs[].src pairs[].dst pairs[].scan_req pairs[].scan_rsp pairs[].connect_ind pairs[].adv_direct pairs[].undecoded
reply_slots[].addr reply_slots[].adverts reply_slots[].adverts_channels reply_slots[].scan_req reply_slots[].connect_ind
reply_slots[].undecoded reply_slots[].undecoded_connect_len reply_slots[].undecoded_scan_len reply_slots[].bad_crc_connect
reply_slots[].guesses[].guess reply_slots[].guesses[].addr reply_slots[].guesses[].count
reply_slots[].competitors[].addr reply_slots[].competitors[].name reply_slots[].competitors[].scan_req reply_slots[].competitors[].connect_ind
attempts[].gid attempts[].id attempts[].ts attempts[].channel attempts[].aa attempts[].crc_init attempts[].init_addr attempts[].adv_addr
attempts[].interval_ms attempts[].latency attempts[].timeout_ms attempts[].hop attempts[].chm_count attempts[].window_ms attempts[].rssi
attempts[].after_adv.seen attempts[].after_adv.gap_us attempts[].after_adv.tifs_ok
attempts[].data.packets attempts[].data.c2p attempts[].data.p2c attempts[].data.empty attempts[].data.payload_bytes
attempts[].data.first_ts attempts[].data.last_ts attempts[].data.first_delay_ms attempts[].data.channels attempts[].data.bad_crc attempts[].data.answer_proof
attempts[].control[].ts attempts[].control[].dir attempts[].control[].opcode attempts[].control[].info attempts[].control[].id
attempts[].outcome attempts[].outcome_detail attempts[].duration_s attempts[].encrypted
attempts[].peripheral_adv.state attempts[].peripheral_adv.first_after_ms attempts[].peripheral_adv.readvertise_taken_ms
connections[].gid connections[].key connections[].aa connections[].crc_init connections[].init_addr connections[].adv_addr
connections[].connect_ts connections[].first_seen connections[].start connections[].interval_ms connections[].data.first_ts connections[].data.last_ts
connections[].data.c2p connections[].data.p2c connections[].outcome connections[].outcome_detail connections[].duration_s connections[].encrypted
candidates[].aa candidates[].alias_of candidates[].score candidates[].first_seen candidates[].last_seen candidates[].packets candidates[].rssi_max
candidates[].near.addr candidates[].near.delta_s candidates[].near.gap_start candidates[].near.gap_end candidates[].near.resumed_after
sniffer.loss[].start sniffer.loss[].end sniffer.loss[].fraction sniffer.loss[].behind sniffer.loss[].slices_lost
sniffer.loss_fraction sniffer.loss_median sniffer.miss_prob.CONNECT_IND sniffer.miss_prob_median.CONNECT_IND sniffer.rate_msps
sniffer.covered_s sniffer.stats_age_s sniffer.stats_rows sniffer.reply.slots sniffer.reply.undecoded sniffer.runs[].first_ts
sniffer.capture_state sniffer.capture_end sniffer.capture_age_s sniffer.newest_row_ts sniffer.dark_s
sniffer.loss_fraction_running sniffer.miss_prob_running
findings[].level findings[].code findings[].text findings[].ts findings[].ids
funnel[].central funnel[].peripheral funnel[].gap funnel[].reached funnel[].pending funnel[].connected.aa funnel[].connected.start
funnel[].steps[].key funnel[].steps[].label funnel[].steps[].count funnel[].steps[].note funnel[].steps[].optional
funnel[].steps[].conns funnel[].steps[].pending
events[].id events[].ts events[].ch events[].kind events[].type events[].src events[].dst events[].dir events[].aa events[].len
events[].rssi events[].crc_ok events[].gap_us events[].attempt events[].conn events[].info
""".split()
PACKET_FIELDS = "id ts channel rssi_dbfs cfo_khz duration_us crc_ok stream_run pdu_type pdu raw decoded[].field decoded[].value".split()
SUGGEST_FIELDS = "devices[].addr devices[].name devices[].vendor devices[].last_seen devices[].packets devices[].roles devices[].addr_type".split()


def has_path(objs, path):
    """True when some object in objs has the whole path (list steps "x[]" try every element)."""
    head, _, rest = path.partition(".")
    for o in objs:
        if not isinstance(o, dict):
            continue
        if head.endswith("[]"):
            v = o.get(head[:-2])
            if isinstance(v, list) and (not rest or has_path(v, rest)):
                if rest or v:
                    return True
        elif head in o:
            if not rest or has_path([o[head]], rest):
                return True
    return False


class PageApiFieldsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.responses = [api(window([PHONE, LOCK])), api(window([SCAN1])), api(window([GHOST])),
                         api(window([PHONE, LOCK], T - 4200, T - 3600)), api(window([PHONE, BEACON]))]
        _, cls.js = page_script()

    def check(self, objs, fields):
        for path in fields:
            leaf = path.split(".")[-1].replace("[]", "")
            pat = r"""[.\[]["']?%s\b|["']%s["']""" % (re.escape(leaf), re.escape(leaf))
            self.assertTrue(re.search(pat, self.js), "the page does not read %s: drop it from the list" % path)
            self.assertTrue(has_path(objs, path), "no response has %s" % path)

    def test_analysis_fields(self):
        self.check(self.responses, FIELDS)

    def test_packet_fields(self):
        r = self.responses[0]
        ids = [a["id"] for a in r["attempts"]][:2] + [e["id"] for e in r["events"] if e["kind"] == "data"][:2]
        self.check([api("/api/follow/packet?id=%d" % i) for i in ids], PACKET_FIELDS)

    def test_suggest_fields(self):
        self.check([api("/api/follow/suggest?q=demo&limit=12")], SUGGEST_FIELDS)

    def test_latest_has_every_followed_address(self):
        for r in self.responses:
            self.assertEqual(sorted(r["latest"]), sorted(r["addrs"]))

    def test_export_links_answer(self):
        for fmt in ("csv", "json", "pcap"):
            status, headers, body = get("/api/follow/export?format=%s&addrs=%s,%s&start=%r&end=%r" % (fmt, PHONE, LOCK, T - 600, T))
            self.assertEqual(status, 200)
            self.assertIn("attachment", headers["Content-Disposition"])
            self.assertTrue(body)

    def test_incremental_poll_shape(self):
        """The page polls with after_id and merges by id: the newer rows come back, the old ones do not."""
        full = self.responses[0]
        ids = sorted(e["id"] for e in full["events"])
        cut = ids[len(ids) // 2]
        inc = api(window([PHONE, LOCK], extra="&after_id=%d" % cut))
        got = sorted(e["id"] for e in inc["events"])
        self.assertEqual(got, [i for i in ids if i > cut])
        self.assertEqual([a["gid"] for a in inc["attempts"]], [a["gid"] for a in full["attempts"]])


# ---- headless Chrome (optional) -------------------------------------------------------------------

DRIVER = r"""
// Runs a plan of steps in headless Chrome over the DevTools protocol; prints one JSON object.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
const [chrome, profile, planFile] = process.argv.slice(2);
const plan = JSON.parse(readFileSync(planFile, "utf8"));
const out = { values: {}, exceptions: [], console: [], timeouts: [], failed: null };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const proc = spawn(chrome, ["--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
  "--no-default-browser-check", "--remote-debugging-port=0", "--user-data-dir=" + profile, "about:blank"],
  { stdio: ["ignore", "ignore", "pipe"] });
let err = "", wsUrl = null;
proc.stderr.on("data", (d) => { err += d; const m = /DevTools listening on (ws:\/\/\S+)/.exec(err); if (m) wsUrl = m[1]; });
async function main() {
  for (let i = 0; i < 300 && !wsUrl; i++) await sleep(50);
  if (!wsUrl) throw new Error("chrome did not start");
  const port = new URL(wsUrl).port;
  let page = null;
  for (let i = 0; i < 60 && !page; i++) {
    const list = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
    page = list.find((t) => t.type === "page");
    if (!page) await sleep(50);
  }
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let id = 0, label = "";
  const pending = new Map(), waiters = [];
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id); pending.delete(msg.id);
      msg.error ? p.j(new Error(JSON.stringify(msg.error))) : p.r(msg.result); return;
    }
    if (msg.method === "Runtime.exceptionThrown") {
      const d = msg.params.exceptionDetails;
      out.exceptions.push(label + ": " + ((d.exception && d.exception.description) || d.text));
    } else if (msg.method === "Runtime.consoleAPICalled" && (msg.params.type === "error" || msg.params.type === "warning")) {
      out.console.push(label + ": " + msg.params.args.map((a) => a.value !== undefined ? a.value : a.description).join(" "));
    }
    for (const w of waiters.slice()) if (w.method === msg.method) { waiters.splice(waiters.indexOf(w), 1); w.r(msg.params); }
  };
  const send = (method, params = {}) => new Promise((r, j) => { const i = ++id; pending.set(i, { r, j }); ws.send(JSON.stringify({ id: i, method, params })); });
  const once = (method) => new Promise((r) => waiters.push({ method, r }));
  const evaluate = async (expr) => {
    const res = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
    if (res.exceptionDetails) throw new Error(label + ": " + expr.slice(0, 120) + ": " +
      ((res.exceptionDetails.exception && res.exceptionDetails.exception.description) || res.exceptionDetails.text));
    return res.result.value;
  };
  await send("Runtime.enable"); await send("Page.enable");
  for (const st of plan) {
    label = st.label || label;
    if (st.op === "open") {
      await send("Emulation.setDeviceMetricsOverride", { width: st.width, height: st.height || 900, deviceScaleFactor: 1, mobile: !!st.mobile });
      await send("Emulation.setTouchEmulationEnabled", { enabled: !!st.mobile, maxTouchPoints: st.mobile ? 5 : 1 });
      const loaded = once("Page.loadEventFired");
      await send("Page.navigate", { url: st.url });
      await loaded;
    } else if (st.op === "wait") {
      const t0 = Date.now(); let ok = false;
      while (Date.now() - t0 < (st.timeout || 20000)) {
        try { if (await evaluate(st.expr)) { ok = true; break; } } catch (e) { /* not yet */ }
        await sleep(100);
      }
      if (!ok) out.timeouts.push(label + ": " + st.expr);
    } else if (st.op === "sleep") await sleep(st.ms);
    else if (st.op === "eval") {
      const v = await evaluate(st.expr);
      if (st.name) out.values[st.name] = v;
    }
  }
  try { await send("Browser.close"); } catch (e) { /* closing */ }
}
main().catch((e) => { out.failed = String(e && e.message || e); }).finally(() => {
  process.stdout.write(JSON.stringify(out));
  try { proc.kill(); } catch (e) { /* gone */ }
  setTimeout(() => process.exit(0), 200);
});
"""


class PageChromeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chrome = _which(CHROME_PATHS, "google-chrome")
        cls.node = _which(NODE_PATHS, "node")
        if not cls.chrome:
            raise unittest.SkipTest("Chrome not installed")
        if not cls.node:
            raise unittest.SkipTest("node not installed")
        r = subprocess.run([cls.node, "-e", "process.exit(typeof WebSocket === 'function' ? 0 : 1)"])
        if r.returncode:
            raise unittest.SkipTest("node has no global WebSocket (needs node >= 22)")
        cls.driver = os.path.join(TMP, "cdp-driver.mjs")
        with open(cls.driver, "w") as f:
            f.write(DRIVER)

    def run_plan(self, plan, timeout=150):
        pf = os.path.join(TMP, "plan.json")
        with open(pf, "w") as f:
            json.dump(plan, f)
        prof = tempfile.mkdtemp(prefix="chrome-", dir=TMP)
        r = subprocess.run([self.node, self.driver, self.chrome, prof, pf], capture_output=True, text=True, timeout=timeout)
        shutil.rmtree(prof, ignore_errors=True)
        out = json.loads(r.stdout or "{}")
        self.assertIsNone(out.get("failed"), out)
        self.assertEqual(out["exceptions"], [], "JavaScript exceptions")
        self.assertEqual(out["timeouts"], [], "conditions never met")
        return out["values"]

    def url(self, query):
        return SRV[1] + "/follow?" + query

    def test_demo_story_renders_and_controls_work(self):
        r = api(window([PHONE, LOCK]))
        first = r["attempts"][0]
        q = "addrs=%s,%s&start=%r&end=%r" % (PHONE, LOCK, T - 600, T)
        ready = "document.querySelector('#funnels .fun') !== null && followDebug().hasRes"
        dbg = "followDebug()"
        v = self.run_plan([
            {"op": "open", "label": "desktop", "url": self.url(q), "width": 1400},
            {"op": "wait", "expr": ready},
            {"op": "eval", "name": "loaded", "expr": dbg},
            {"op": "eval", "name": "dom", "expr": """({funnels: document.querySelectorAll('#funnels .fun').length,
                finds: document.querySelectorAll('#finds li.fd').length,
                rows: document.querySelectorAll('#attwrap tr[data-gid]').length,
                steps: document.querySelectorAll('#funnels li.st').length,
                lanesH: document.getElementById('tl').clientHeight,
                url: location.search, wide: document.documentElement.scrollWidth,
                exp: Array.from(document.querySelectorAll('#expbody a')).map((a) => a.getAttribute('href'))})"""},
            # an attempt row zooms the timeline to it and lists its packets
            {"op": "eval", "expr": "document.querySelector('tr[data-gid=\"%s\"]').click()" % first["gid"]},
            {"op": "sleep", "ms": 400},
            {"op": "eval", "name": "scoped", "expr": dbg},
            {"op": "eval", "name": "detailbox", "expr": "!document.getElementById('attx').hidden"},
            # a packet row opens its decoded fields
            {"op": "eval", "expr": "document.querySelector('#prows .pr').click()"},
            {"op": "wait", "expr": "document.querySelector('#detail table.kv') !== null"},
            {"op": "eval", "name": "detail", "expr": "document.querySelector('#detail .dh b').textContent"},
            # clear both, then wheel zoom and double-click reset on the canvas
            {"op": "eval", "expr": "document.querySelector('[data-clear=\"scope\"]').click()"},
            {"op": "eval", "expr": "document.querySelector('[data-clear=\"view\"]').click()"},
            {"op": "sleep", "ms": 300},
            {"op": "eval", "name": "cleared", "expr": dbg},
            {"op": "eval", "expr": """(() => { const c = document.getElementById('tl'), b = c.getBoundingClientRect();
                c.dispatchEvent(new WheelEvent('wheel', {deltaY: -900, clientX: b.left + b.width / 2, clientY: b.top + 40, bubbles: true, cancelable: true})); })()"""},
            {"op": "sleep", "ms": 300},
            {"op": "eval", "name": "zoomed", "expr": dbg},
            {"op": "eval", "expr": "document.getElementById('tl').dispatchEvent(new MouseEvent('dblclick', {bubbles: true}))"},
            {"op": "sleep", "ms": 300},
            {"op": "eval", "name": "reset", "expr": dbg},
            # type filter and text filter
            {"op": "eval", "expr": "document.querySelector('[data-cat=\"adv\"]').click()"},
            {"op": "eval", "name": "noadv", "expr": dbg},
            {"op": "eval", "expr": "document.querySelector('[data-cat=\"adv\"]').click()"},
            {"op": "eval", "expr": "(() => { const q = document.getElementById('pq'); q.value = 'CONNECT_IND'; q.dispatchEvent(new Event('input')); })()"},
            {"op": "sleep", "ms": 400},
            {"op": "eval", "name": "textfilter", "expr": dbg},
            # typing / pasting addresses: several at once, any format; junk is refused
            {"op": "eval", "expr": """(() => { const i = document.getElementById('addin'); i.value = 'd0aabbccdd01 zz';
                i.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true})); })()"""},
            {"op": "wait", "expr": "followDebug().addrs.length === 3 && followDebug().hasRes"},
            {"op": "eval", "name": "added", "expr": "({d: followDebug(), url: location.search, left: document.getElementById('addin').value})"},
        ])
        loaded, dom = v["loaded"], v["dom"]
        self.assertEqual(loaded["mode"], "fixed")
        self.assertIsNone(loaded["lastErr"])
        self.assertEqual(loaded["events"], r["events_total"])
        self.assertEqual(loaded["lanes"], ["snf", "adv", "adv", "dir", "conn"])
        self.assertEqual(dom["funnels"], len(r["funnel"]))
        self.assertEqual(dom["steps"], sum(len(f["steps"]) for f in r["funnel"]))
        self.assertEqual(dom["rows"], len(r["attempts"]) + len(r["connections"]))
        self.assertGreaterEqual(dom["finds"], min(6, len(r["findings"])))
        self.assertGreater(dom["lanesH"], 150)
        self.assertLessEqual(dom["wide"], 1400)
        self.assertEqual(len(dom["exp"]), 3)
        self.assertTrue(all("start=" in h and "end=" in h for h in dom["exp"]))
        self.assertEqual(v["scoped"]["scope"], "group")
        self.assertIsNotNone(v["scoped"]["view"])
        self.assertEqual(v["scoped"]["listed"], first["data"]["packets"] + 1)      # its data + the request itself
        self.assertTrue(v["detailbox"])
        self.assertRegex(v["detail"], r"^#\d+ \w+")
        self.assertIsNone(v["cleared"]["scope"])
        self.assertIsNone(v["cleared"]["view"])
        self.assertIsNotNone(v["zoomed"]["view"])
        self.assertLess(v["zoomed"]["listed"], v["cleared"]["listed"])
        self.assertIsNone(v["reset"]["view"])
        self.assertLess(v["noadv"]["listed"], v["reset"]["listed"])
        hay = lambda e: " ".join(str(e.get(k) or "") for k in ("type", "src", "dst", "aa", "info")).lower()
        n_ci = sum(1 for e in r["events"] if "connect_ind" in hay(e))     # requests, and replies of their length
        self.assertGreater(n_ci, sum(1 for e in r["events"] if e["type"] == "CONNECT_IND"))
        self.assertEqual(v["textfilter"]["listed"], n_ci)
        added = v["added"]
        self.assertEqual(added["d"]["addrs"], [PHONE, LOCK, BEACON])
        self.assertIn("addrs=%s,%s,%s" % (PHONE, LOCK, BEACON), added["url"])
        self.assertEqual(added["left"], "zz")

    def test_hostile_strings_stay_text(self):
        q = "addrs=%s,%s&start=%r&end=%r" % (BEACON, PHONE, T - 600, T)
        labels = json.dumps({PHONE: HOSTILE})
        ready = "document.querySelector('#funnels .fun') !== null && followDebug().hasRes"
        v = self.run_plan([
            {"op": "open", "label": "hostile", "url": self.url(q), "width": 1400},
            {"op": "wait", "expr": ready},
            {"op": "eval", "expr": "localStorage.setItem('follow.labels', %s)" % json.dumps(labels)},
            {"op": "open", "url": self.url(q), "width": 1400},
            {"op": "wait", "expr": ready},
            {"op": "eval", "expr": "document.querySelector('#prows .pr').click()"},
            {"op": "wait", "expr": "document.querySelector('#detail table.kv') !== null"},
            {"op": "eval", "name": "res", "expr": """({xss: window.__xss === 1, imgs: document.querySelectorAll('img').length,
                bolds: document.querySelectorAll('main b, .bars b').length,
                text: document.body.textContent.split(%s).length - 1})""" % json.dumps(HOSTILE)},
            {"op": "eval", "name": "boldtexts", "expr": "Array.from(document.querySelectorAll('b')).map((b) => b.textContent).filter((t) => t === '')"},
            {"op": "eval", "name": "hint", "expr": "Array.from(document.querySelectorAll('#funnels .fnote.w')).map((e) => e.textContent).join(' | ')"},
        ])
        self.assertFalse(v["res"]["xss"])
        self.assertEqual(v["res"]["imgs"], 0)
        self.assertGreaterEqual(v["res"]["text"], 3, "the name and the label show as text (chips, devices, rows)")
        self.assertEqual(v["boldtexts"], [], "no empty <b> injected by a string")
        # the beacon is heard, but advertises only non-connectable PDUs: say that, not "check the address"
        self.assertIn("only non-connectable", v["hint"])
        self.assertNotIn("resolvable private address", v["hint"])

    def test_phone_width(self):
        q = "addrs=%s,%s&start=%r&end=%r" % (PHONE, LOCK, T - 600, T)
        v = self.run_plan([
            {"op": "open", "label": "phone", "url": self.url(q), "width": 390, "height": 844, "mobile": True},
            {"op": "wait", "expr": "document.querySelector('#funnels .fun') !== null && followDebug().hasRes"},
            {"op": "eval", "expr": "document.querySelector('tr[data-gid]').click()"},
            {"op": "sleep", "ms": 300},
            {"op": "eval", "name": "w", "expr": """({page: document.documentElement.scrollWidth,
                over: Array.from(document.querySelectorAll('body *')).filter((e) => { const r = e.getBoundingClientRect();
                  return r.width && r.right > 391 && !e.closest('.scroll, .pills, ol.steps, .pv'); }).map((e) => e.tagName + '.' + e.className).slice(0, 5),
                rowH: document.querySelector('#prows .pr') ? document.querySelector('#prows .pr').getBoundingClientRect().height : 0})"""},
        ])
        self.assertLessEqual(v["w"]["page"], 390)
        self.assertEqual(v["w"]["over"], [])
        self.assertGreater(v["w"]["rowH"], 30, "two-line packet rows at phone width")

    def test_live_polls_and_server_errors(self):
        ready = "followDebug().hasRes || followDebug().lastErr"
        v = self.run_plan([
            {"op": "open", "label": "live", "url": self.url("addrs=%s&span=600" % LOCK), "width": 1400},
            {"op": "wait", "expr": ready},
            {"op": "sleep", "ms": 4500},
            {"op": "eval", "name": "live", "expr": "followDebug()"},
            {"op": "eval", "name": "pill", "expr": "document.getElementById('status').textContent"},
            # the capture behind it stops while the server keeps answering: red pill, banner, verdicts greyed.
            # (The demo's own capture ends with its story, so the test sets both states itself.)
            {"op": "eval", "expr": """(() => { const real = window.fetch; window.__realFetch = real; window.__cap = 'running';
                window.fetch = async (u, o) => { const r = await real(u, o); if (!String(u).startsWith('/api/follow?')) return r;
                  const b = await r.json(), now = Date.now() / 1000, age = window.__cap === 'running' ? 0 : 125;
                  b.sniffer.capture_state = window.__cap; b.sniffer.capture_end = now - age; b.sniffer.capture_age_s = age;
                  return new Response(JSON.stringify(b), {status: 200}); }; })()"""},
            {"op": "wait", "expr": "!followDebug().capStale"},
            {"op": "eval", "name": "capok", "expr": "document.getElementById('status').textContent"},
            {"op": "eval", "expr": "window.__cap = 'stopped'"},
            {"op": "wait", "expr": "followDebug().capStale"},
            {"op": "eval", "name": "capstop", "expr": """({pill: document.getElementById('status').textContent, banner: document.getElementById('banner').textContent,
                grey: document.getElementById('main').classList.contains('capstale'), stale: followDebug().stale})"""},
            {"op": "eval", "expr": "window.fetch = window.__realFetch"},
            {"op": "eval", "expr": "document.getElementById('pause').click()"},
            {"op": "eval", "name": "paused", "expr": "followDebug()"},
            # the server's time budget refuses the live window: say so, offer shorter windows, stop polling
            {"op": "eval", "expr": "document.getElementById('pause').click()"},
            {"op": "eval", "expr": """(() => { const real = window.fetch; window.fetch = (u, o) => String(u).startsWith('/api/follow?')
                ? Promise.resolve(new Response(JSON.stringify({error: 'this window is too large for the database: its queries took longer than 20 s'}), {status: 400}))
                : real(u, o); })()"""},
            {"op": "wait", "expr": "followDebug().lastErr !== null"},
            {"op": "eval", "name": "slow1", "expr": "followDebug().polls"},
            {"op": "sleep", "ms": 6000},
            {"op": "eval", "name": "slow2", "expr": """({polls: followDebug().polls, stale: followDebug().stale, grey: document.getElementById('main').classList.contains('stale'),
                banner: document.getElementById('banner').textContent, tries: document.querySelectorAll('#banner [data-span]').length})"""},
            {"op": "open", "label": "too long", "url": self.url("addrs=%s&start=%r&end=%r" % (LOCK, T - 8 * 3600, T)), "width": 1400},
            {"op": "wait", "expr": ready},
            {"op": "sleep", "ms": 2500},
            {"op": "eval", "name": "err", "expr": """({d: followDebug(), banner: document.getElementById('banner').textContent,
                hidden: document.getElementById('banner').hidden, diag: document.getElementById('funnels').textContent})"""},
            # a busy server (503 busy) is retried soon, also in a fixed window, which does not poll
            {"op": "open", "label": "busy", "url": self.url("addrs=%s&start=%r&end=%r" % (LOCK, T - 60, T)), "width": 1400},
            {"op": "wait", "expr": "followDebug().hasRes"},
            {"op": "eval", "expr": """(() => { const real = window.fetch; let n = 0;
                window.fetch = (u, o) => String(u).startsWith('/api/follow?') && n++ === 0
                  ? Promise.resolve(new Response(JSON.stringify({error: 'the server is busy with other follow analyses: retrying', busy: true}), {status: 503}))
                  : real(u, o); document.getElementById('others').click(); })()"""},
            {"op": "wait", "expr": "followDebug().polls >= 3 && followDebug().hasRes && !followDebug().lastErr", "timeout": 10000},
            {"op": "eval", "name": "busy", "expr": "followDebug()"},
            {"op": "open", "label": "nothing", "url": self.url("addrs=%s&start=%r&end=%r" % (GHOST, T - 600, T)), "width": 1400},
            {"op": "wait", "expr": ready},
            {"op": "eval", "name": "ghost", "expr": """({gap: document.querySelector('#funnels li.st.gap span').textContent,
                pempty: document.getElementById('pempty').textContent, devs: document.getElementById('devs').textContent})"""},
            {"op": "open", "label": "empty", "url": SRV[1] + "/follow", "width": 1400},
            {"op": "sleep", "ms": 500},
            {"op": "eval", "name": "intro", "expr": "({intro: !document.getElementById('intro').hidden, diag: document.getElementById('diag').hidden})"},
        ])
        live = v["live"]
        self.assertEqual(live["mode"], "live")
        self.assertGreaterEqual(live["polls"], 2, "polls every 2 s")
        self.assertIsNone(live["lastErr"])
        self.assertFalse(live["stale"])
        self.assertIn("live", v["pill"])
        self.assertNotIn("capture", v["capok"])
        cs = v["capstop"]
        self.assertIn("capture stopped", cs["pill"])
        self.assertIn("2 min", cs["pill"])
        self.assertIn("capture stopped", cs["banner"])
        self.assertTrue(cs["grey"], "the verdicts are greyed out")
        self.assertFalse(cs["stale"], "polling itself still works")
        self.assertTrue(v["paused"]["paused"])
        slow = v["slow2"]
        self.assertEqual(slow["polls"], v["slow1"], "a 400 is not retried by itself")
        self.assertTrue(slow["stale"] and slow["grey"], "the old data is greyed out")
        self.assertIn("too large", slow["banner"])
        self.assertGreaterEqual(slow["tries"], 1, "shorter windows offered")
        err = v["err"]
        self.assertFalse(err["hidden"])
        self.assertIn("400", err["banner"])
        self.assertIn("6 h", err["banner"])
        self.assertEqual(err["d"]["polls"], 1, "a 400 is not retried by itself")
        self.assertNotIn("Loading", err["diag"])
        self.assertEqual((v["busy"]["mode"], v["busy"]["polls"]), ("fixed", 3), "the busy answer was retried once")
        self.assertEqual(v["ghost"]["gap"], "Peripheral advertising heard")
        self.assertIn("No packet", v["ghost"]["pempty"])
        self.assertIn("not heard", v["ghost"]["devs"])
        self.assertTrue(v["intro"]["intro"])
        self.assertTrue(v["intro"]["diag"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
