# app.py
import os, json, time, hmac, base64, hashlib, asyncio, httpx, html as html_lib, re
from bs4 import BeautifulSoup
from fastapi import FastAPI, Form, Cookie, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Optional, List, Dict, Any
from urllib.parse import quote

app = FastAPI(title="Testbook Mirror", version="38.0.0")
BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"

COUNT_API = f"{API_BASE}/api/v2_1/live-panel/count"
ALL_API = f"{API_BASE}/api/v2_1/live-panel/all"

# ---------- Token helpers ----------
def sign_token(token: str) -> str:
    data = base64.urlsafe_b64encode(token.encode()).decode()
    sig = hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{data}.{sig}"

def unsign_token(cookie: str) -> Optional[str]:
    try:
        data, sig = cookie.rsplit(".", 1)
        if not hmac.compare_digest(sig, hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]): return None
        return base64.urlsafe_b64decode(data.encode()).decode()
    except: return None

def get_token(c): return unsign_token(c) if c else None

def decode_jwt_payload(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3: return None
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except: return None

def validate_jwt(token: str):
    p = decode_jwt_payload(token)
    if p is None: return False, "Invalid JWT"
    if p.get("exp") and p["exp"] < time.time(): return False, "Token expired"
    return True, "ok"

def get_user_info(token: str) -> dict:
    p = decode_jwt_payload(token) or {}
    return {"name": p.get("name") or "User", "email": p.get("email") or "", "isPaid": p.get("isPaidUser", False)}

def tb_headers(token: str, html_mode: bool = False) -> Dict[str, str]:
    h = {
        "Authorization": f"Bearer {token}", "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" if html_mode else "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "identity",
        "Referer": BASE_URL + "/", "Origin": BASE_URL,
        "Cookie": f"tb_token={token}",
    }
    return h

def _clean(s) -> str:
    if s is None: return ""
    s = str(s)
    for _ in range(4):
        n = html_lib.unescape(s)
        if n == s: break
        s = n
    try: s = BeautifulSoup(s, "html.parser").get_text()
    except: pass
    return " ".join(s.replace("\u00a0", " ").replace("\t", " ").split()).strip()

async def fetch_stats(token: str) -> Optional[dict]:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{COUNT_API}?auth_code={quote(token,safe='')}&language=english", headers=tb_headers(token))
            if r.status_code == 200 and r.json().get("success"): return r.json().get("data", {})
    except: pass
    return None

# =============================================
# APPROACH 1: HTML SCRAPING with embedded JSON
# =============================================
async def scrape_page_for_series(token: str, path: str) -> Dict:
    """Fetch page HTML and extract series from embedded JSON + DOM."""
    result = {"series": [], "scripts_info": [], "dom_series": [], "html_len": 0}
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=20) as client:
            r = await client.get(BASE_URL + path, headers=tb_headers(token, html_mode=True))
            result["html_len"] = len(r.text)
            if r.status_code != 200:
                return result

            soup = BeautifulSoup(r.text, "html.parser")

            # 1. Look for embedded JSON in script tags
            for sc in soup.find_all("script"):
                sid = sc.get("id") or ""
                stype = sc.get("type") or ""
                content = sc.string or ""
                if not content.strip(): continue

                # Angular TransferState / state scripts
                if "state" in sid.lower() or "json" in stype or "ng-state" in sid.lower():
                    result["scripts_info"].append({"id": sid, "type": stype, "len": len(content)})
                    try:
                        data = json.loads(content)
                        # Walk for series
                        found = []
                        _walk_any_series(data, found)
                        result["series"].extend(found)
                    except Exception:
                        pass

            # 2. Look in inline <script> for window.__STATE__ = {...}
            for sc in soup.find_all("script"):
                txt = sc.string or ""
                if not txt or len(txt) < 200: continue
                for var in ("__INITIAL_STATE__", "__APP_STATE__", "__DATA__", "window.__state", "__NG_STATE__"):
                    m = re.search(re.escape(var) + r"\s*=\s*(\{.*?\});", txt, re.DOTALL)
                    if m:
                        try:
                            data = json.loads(m.group(1))
                            found = []
                            _walk_any_series(data, found)
                            result["series"].extend(found)
                        except Exception:
                            pass

            # 3. DOM scraping — find links with /test-series/
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if "/test-series/" not in href: continue
                title = a.get_text(" ", strip=True)
                if not title or len(title) < 5: continue
                # Extract TSID from href
                parts = href.rstrip("/").split("/")
                tid = ""
                for i, p in enumerate(parts):
                    if p == "test-series" and i + 1 < len(parts):
                        tid = parts[i+1]
                        break
                if tid and len(tid) > 8:
                    result["dom_series"].append({"id": tid, "title": title, "href": href})
    except Exception as e:
        result["error"] = str(e)
    return result

def _walk_any_series(node, out, depth=0):
    if depth > 15: return
    if isinstance(node, list):
        for x in node: _walk_any_series(x, out, depth+1)
    elif isinstance(node, dict):
        k = set(node.keys())
        # Series detector: has id + name, AND has progress-ish OR test count OR link pattern
        has_id = ("id" in k or "_id" in k or "seriesId" in k or "testSeriesId" in k or "tsid" in k)
        has_name = ("name" in k or "title" in k or "seriesName" in k)
        has_meta = bool(k & {"totalTests", "testsCount", "totalQuestions", "attempted",
                              "testsAttempted", "completedTests", "purchased", "enrolled",
                              "progress", "price", "type"})
        # Exclude question-like objects
        not_question = not bool(k & {"posMarks", "negMarks", "questionCount", "questionText"})
        if has_id and has_name and has_meta and not_question:
            sid = str(node.get("id") or node.get("_id") or node.get("seriesId") or node.get("testSeriesId") or node.get("tsid") or "")
            if sid and len(sid) > 8:
                out.append({
                    "id": sid,
                    "title": _clean(node.get("name") or node.get("title") or node.get("seriesName") or ""),
                    "totalTests": node.get("totalTests") or node.get("testsCount") or 0,
                    "attempted": node.get("attempted") or node.get("testsAttempted") or 0,
                    "slug": node.get("slug") or "",
                })
        for v in node.values():
            if isinstance(v, (list, dict)): _walk_any_series(v, out, depth+1)

# =============================================
# APPROACH 2: More endpoint attempts (POST + variants)
# =============================================
def more_endpoints(token: str) -> List[Dict]:
    """Return list of {m: GET/POST, u: url, b: body}"""
    urls = []
    # GET variants on live-panel
    for ep in ["enrolled", "enrolled-series", "enrolled-test-series", "my-series",
               "my-test-series", "my-courses", "recent-series", "recent-test-series",
               "dashboard", "home", "panel", "panel-data", "user-series", "user-test-series",
               "series", "all-series", "purchased", "purchased-series", "purchased-test-series",
               "subscriptions", "user-subscriptions", "me", "user", "profile",
               "activity", "recent-activity", "continue-watching", "resume"]:
        urls.append({"m": "GET", "u": f"{API_BASE}/api/v2_1/live-panel/{ep}"})
        urls.append({"m": "GET", "u": f"{API_BASE}/api/v2_1/live-panel/{ep}?page=1&limit=50"})

    # Me-based
    for ep in ["enrolled", "test-series", "series", "dashboard", "home", "my-series", "purchased"]:
        urls.append({"m": "GET", "u": f"{API_BASE}/api/v2_1/me/{ep}"})
        urls.append({"m": "GET", "u": f"{API_BASE}/api/v2_1/users/me/{ep}"})

    # v2 variants
    for ep in ["enrolled", "test-series", "my-series", "dashboard"]:
        urls.append({"m": "GET", "u": f"{API_BASE}/api/v2/me/{ep}"})
        urls.append({"m": "GET", "u": f"{API_BASE}/api/v2/users/me/{ep}"})

    # All with query params
    urls.append({"m": "GET", "u": f"{ALL_API}?type=enrolled"})
    urls.append({"m": "GET", "u": f"{ALL_API}?enrolled=true"})
    urls.append({"m": "GET", "u": f"{ALL_API}?view=enrolled"})
    urls.append({"m": "GET", "u": f"{ALL_API}?include=enrolled"})

    return urls

async def try_more_endpoints(token: str) -> Dict:
    urls = more_endpoints(token)
    result = {"hits": [], "raw_dumps": []}
    async with httpx.AsyncClient(follow_redirects=True, timeout=8) as client:
        async def try_one(e):
            u = e["u"]
            full = f"{u}{'&' if '?' in u else '?'}auth_code={quote(token,safe='')}&language=english"
            try:
                if e["m"] == "GET":
                    r = await client.get(full, headers=tb_headers(token))
                else:
                    r = await client.post(full, headers=tb_headers(token), json=e.get("b", {}))
                if r.status_code != 200: return None
                try: j = r.json()
                except: return None
                if not isinstance(j, dict) or not j.get("success"): return None
                # Look for anything series-like
                data = j.get("data", {})
                # Get ALL keys with their types
                keys_info = []
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(v, list): keys_info.append(f"{k}(list,{len(v)})")
                        elif isinstance(v, dict): keys_info.append(f"{k}(dict,{len(v)})")
                        else: keys_info.append(f"{k}={str(v)[:30]}")
                elif isinstance(data, list):
                    keys_info = [f"list(len={len(data)})"]

                found = []
                _walk_any_series(data, found)
                return {"url": u, "series_count": len(found), "keys": keys_info,
                        "preview": json.dumps(data, ensure_ascii=False)[:400], "series": found}
            except Exception: return None

        results = await asyncio.gather(*[try_one(e) for e in urls], return_exceptions=True)

    for res in results:
        if not res or isinstance(res, Exception): continue
        result["hits"].append({
            "url": res["url"], "series_count": res["series_count"],
            "keys": res["keys"][:8], "preview": res["preview"]
        })
        result["raw_dumps"].extend(res["series"])
    return result

# =============================================
# Series tests (unchanged)
# =============================================
def build_series_test_urls(tsid: str, slug: str) -> List[str]:
    s = quote(tsid, safe="")
    urls = [
        f"{ALL_API}?tsid={s}",
        f"{API_BASE}/api/v2_1/live-panel/test-series/{s}",
        f"{API_BASE}/api/v2_1/live-panel/test-series/{s}/tests",
        f"{API_BASE}/api/v2_1/test-series/{s}/tests",
        f"{API_BASE}/api/v2_1/tests?tsid={s}",
    ]
    return urls

def _walk_tests(node, out, depth=0):
    if depth > 15: return
    if isinstance(node, list):
        for x in node: _walk_tests(x, out, depth+1)
    elif isinstance(node, dict):
        k = set(node.keys())
        is_test = (("id" in k or "_id" in k) and ("title" in k or "name" in k) and
                   bool(k & {"questionCount","duration","totalMark","totalMarks","testType","posMarks"}))
        if is_test: out.append(node)
        for v in node.values():
            if isinstance(v, (list, dict)): _walk_tests(v, out, depth+1)

def norm_tests(raw):
    seen, out = set(), []
    for t in raw:
        tid = str(t.get("id") or t.get("_id") or "")
        if not tid or tid in seen: continue
        seen.add(tid)
        out.append({"id": tid, "title": _clean(t.get("title") or t.get("name") or "Test"),
                    "questionCount": t.get("questionCount") or 0,
                    "duration": t.get("duration") or 0,
                    "totalMarks": t.get("totalMarks") or t.get("totalMark") or 0,
                    "isFree": bool(t.get("isFree"))})
    return out

async def fetch_series_tests(token: str, tsid: str, slug: str = "") -> Dict:
    result = {"tests": [], "winner": None}
    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
        async def try_u(u):
            full = f"{u}{'&' if '?' in u else '?'}auth_code={quote(token,safe='')}&language=english"
            try:
                r = await client.get(full, headers=tb_headers(token))
                if r.status_code != 200: return None
                j = r.json()
                if not isinstance(j, dict) or not j.get("success"): return None
                raw = []
                _walk_tests(j.get("data", {}), raw)
                return {"url": u, "raw": raw}
            except: return None
        results = await asyncio.gather(*[try_u(u) for u in build_series_test_urls(tsid, slug)], return_exceptions=True)
        all_raw = []
        for res in results:
            if isinstance(res, Exception) or not res: continue
            if res["raw"]:
                all_raw.extend(res["raw"])
                if not result["winner"]: result["winner"] = res["url"]
        result["tests"] = norm_tests(all_raw)
    return result

# ---------- Questions ----------
def extract_questions(data: dict) -> List[Dict]:
    out = []
    for sec in data.get("sections", []):
        for q in sec.get("questions", []):
            if not isinstance(q, dict): continue
            def _parse(lb):
                if not isinstance(lb, dict): return {"text": "", "options": [], "correctIndex": -1}
                txt = _clean(lb.get("value") or lb.get("questionText") or "")
                opts, ci = [], -1
                for i, o in enumerate(lb.get("options") or []):
                    if isinstance(o, dict):
                        opts.append(_clean(o.get("value") or o.get("text") or ""))
                        if o.get("isCorrect") is True or o.get("correct") is True: ci = i
                    else: opts.append(_clean(str(o)))
                return {"text": txt, "options": opts, "correctIndex": ci}
            en = _parse(q.get("en") or {}); hi = _parse(q.get("hi") or {})
            pri = en if en["text"] else hi
            out.append({"id": q.get("_id") or "", "text": pri["text"], "options": pri["options"],
                        "text_en": en["text"], "options_en": en["options"],
                        "text_hi": hi["text"], "options_hi": hi["options"],
                        "posMarks": q.get("posMarks", 4), "negMarks": q.get("negMarks", 1),
                        "correctIndex": pri["correctIndex"]})
    return out

async def fetch_questions(token: str, tid: str) -> Dict:
    res = {"questions": [], "test_info": None, "error": None}
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(f"{API_BASE}/api/v2_1/tests/{quote(tid,safe='')}?auth_code={quote(token,safe='')}&language=english", headers=tb_headers(token))
            if r.status_code != 200: res["error"] = f"HTTP {r.status_code}"; return res
            j = r.json()
            if not j.get("success"): res["error"] = "API error"; return res
            d = j.get("data", {})
            dur = d.get("duration") or 0
            if dur > 1000: dur = dur // 60
            res["test_info"] = {"title": _clean(d.get("title") or "Test"), "duration": dur,
                                "totalQuestions": sum(len(s.get("questions", [])) for s in d.get("sections", []))}
            res["questions"] = extract_questions(d)
    except Exception as e: res["error"] = str(e)
    return res

# ---------- Handlers ----------
@app.exception_handler(StarletteHTTPException)
async def http_exc(req: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and req.url.path == "/": return RedirectResponse("/")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

@app.exception_handler(Exception)
async def all_exc(req: Request, exc: Exception):
    import traceback; tb = traceback.format_exc(); print(tb)
    return HTMLResponse(f"<h1>Error</h1><pre>{tb}</pre>", status_code=500)

# ---------- CSS ----------
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f4f8;color:#1a202c}
.topbar{background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff;padding:14px 18px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;flex-wrap:wrap;gap:8px}
.topbar h1{font-size:16px;font-weight:700}
.topbar .nav{display:flex;gap:6px;font-size:12px;flex-wrap:wrap}
.topbar .nav a{color:#fff;text-decoration:none;padding:6px 12px;background:rgba(255,255,255,.18);border-radius:8px;font-weight:600}
.container{max-width:920px;margin:0 auto;padding:18px}
.section-title{font-size:14px;font-weight:700;color:#4a5568;margin:20px 0 12px;text-transform:uppercase;letter-spacing:.5px}
.card{background:#fff;border-radius:14px;padding:16px;margin-bottom:12px;box-shadow:0 2px 10px rgba(0,0,0,.06);border-left:4px solid #4f46e5}
.card a{text-decoration:none;color:#1a202c;display:block}
.card h3{font-size:14px;font-weight:700;margin-bottom:6px;line-height:1.4}
.card p{font-size:12px;color:#718096;line-height:1.55;margin-top:4px}
.badge{display:inline-block;background:#eef2ff;color:#4f46e5;font-size:10px;font-weight:700;padding:3px 9px;border-radius:12px;margin-top:8px;text-transform:uppercase}
.badge.green{background:#d1fae5;color:#059669}
.row{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.series-card{background:#fff;border-radius:14px;padding:16px;box-shadow:0 2px 10px rgba(0,0,0,.06);border-left:4px solid #1fbad6}
.series-card a{text-decoration:none;color:#1a202c;display:block}
.series-card h3{font-size:14px;font-weight:700;margin-bottom:8px;line-height:1.4}
.series-card .progress-row{display:flex;justify-content:space-between;font-size:12px;color:#4a5568;margin-bottom:6px}
.series-card .progress-bar{height:5px;background:#e2e8f0;border-radius:3px;overflow:hidden}
.series-card .progress-bar .fill{height:100%;background:#1fbad6;border-radius:3px}
.series-card .btn-go{display:block;margin-top:12px;padding:10px;background:#1fbad6;color:#fff;text-align:center;border-radius:8px;font-weight:700;font-size:13px}
.empty{text-align:center;padding:40px 20px;color:#a0aec0}
.empty h2{font-size:18px;margin-bottom:8px;color:#4a5568}
.btn{display:inline-block;padding:11px 20px;background:#4f46e5;color:#fff;border:none;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;cursor:pointer}
.info-box{background:#eef2ff;border-radius:12px;padding:14px;margin-bottom:16px;font-size:13px;color:#3730a3;line-height:1.7}
.stat-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.stat{background:#fff;padding:12px 16px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.05);flex:1;min-width:110px;text-align:center}
.stat .num{font-size:24px;font-weight:800;color:#4f46e5}
.stat .lbl{font-size:11px;color:#718096;text-transform:uppercase;margin-top:4px}
.debug{background:#1a202c;color:#a0aec0;padding:14px;border-radius:10px;font-family:monospace;font-size:11px;overflow:auto;max-height:600px;line-height:1.5;white-space:pre-wrap;word-break:break-word}
.back-btn{display:inline-block;margin-bottom:14px;padding:8px 16px;background:#e2e8f0;color:#4a5568;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600}
.spinner{display:inline-block;width:36px;height:36px;border:4px solid #e2e8f0;border-top-color:#4f46e5;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.loading-box{text-align:center;padding:50px 20px}
.loading-box p{margin-top:16px;color:#718096;font-size:14px}
.search-box{display:flex;gap:8px;margin-bottom:18px}
.search-box input{flex:1;padding:12px 16px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:14px;outline:none}
.search-box button{padding:12px 20px;background:#4f46e5;color:#fff;border:none;border-radius:10px;font-weight:600;cursor:pointer}
.tb-header{background:#fff;padding:12px 16px;position:sticky;top:56px;z-index:40;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.tb-header .q-num-big{font-size:24px;font-weight:800;min-width:36px}
.tb-header .q-stats{display:flex;gap:16px;font-size:12px;flex:1}
.tb-header .q-stat{display:flex;flex-direction:column;align-items:center}
.tb-header .q-stat .lbl{font-size:10px;color:#718096;text-transform:uppercase}
.tb-header .q-stat .val{font-size:13px;font-weight:700}
.marks-pos{color:#10b981}.marks-neg{color:#ef4444}
.timer-box{background:#1a202c;color:#fff;padding:6px 14px;border-radius:8px;font-family:monospace;font-size:14px;font-weight:700}
.lang-select{padding:6px 12px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:13px;font-weight:600;color:#4a5568;background:#fff;cursor:pointer}
.tb-question{padding:20px 16px;background:#fff}
.tb-question .q-text{font-size:16px;line-height:1.7;margin-bottom:20px;word-break:break-word;white-space:pre-wrap}
.tb-opt{display:flex;align-items:flex-start;gap:12px;padding:14px 16px;background:#fff;border:1.5px solid #e2e8f0;border-radius:10px;margin-bottom:12px;cursor:pointer;font-size:15px;line-height:1.5;user-select:none}
.tb-opt:hover{border-color:#a5b4fc;background:#f8faff}
.tb-opt.selected{border-color:#4f46e5;background:#eef2ff}
.tb-opt .radio{width:22px;height:22px;min-width:22px;border:2px solid #cbd5e0;border-radius:50%;display:flex;align-items:center;justify-content:center;margin-top:1px}
.tb-opt.selected .radio{border-color:#4f46e5;background:#4f46e5}
.tb-opt.selected .radio::after{content:'';width:8px;height:8px;background:#fff;border-radius:50%}
.tb-opt .opt-text{flex:1;word-break:break-word}
.tb-nav{background:#fff;padding:12px 16px;display:flex;gap:10px;flex-wrap:wrap;border-top:1px solid #e2e8f0;position:sticky;bottom:0;box-shadow:0 -2px 10px rgba(0,0,0,.05)}
.tb-nav button{flex:1;min-width:100px;padding:12px;border:none;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;background:#e2e8f0;color:#4a5568}
.tb-nav .btn-save{background:#1fbad6;color:#fff}
.tb-nav .btn-submit{background:#10b981;color:#fff}
.progress-bar{height:3px;background:#e2e8f0;position:sticky;top:104px;z-index:39}
.progress-bar .fill{height:100%;background:linear-gradient(90deg,#4f46e5,#7c3aed)}
.result-box{background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff;padding:24px;border-radius:14px;text-align:center;margin:16px}
.result-box .score{font-size:42px;font-weight:900;margin:8px 0}
.result-box .lbl{font-size:13px;opacity:.9}
.q-indicators{display:flex;flex-wrap:wrap;gap:4px;padding:12px 16px;background:#fff;border-bottom:1px solid #e2e8f0}
.q-indicator{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:6px;background:#e2e8f0;color:#4a5568;font-size:11px;font-weight:700;cursor:pointer}
.q-indicator.answered{background:#4f46e5;color:#fff}
.q-indicator.current{outline:2px solid #4f46e5;outline-offset:1px}
"""

def shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Testbook Mirror</title><style>{CSS}</style></head><body>
<div class="topbar"><h1>📚 Testbook Mirror</h1>
<div class="nav"><a href="/dashboard">🏠 Home</a><a href="/online-test-series">📝 Series</a>
<a href="/search">🔍 Search</a><a href="/debug/probe">🐛 Debug</a><a href="/logout">Logout</a></div></div>
{body}</body></html>"""

LOGIN_HTML = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:18px;box-shadow:0 20px 60px rgba(0,0,0,.3);padding:40px;width:100%;max-width:500px}
h1{font-size:22px;text-align:center;margin-bottom:6px}
p.sub{color:#718096;font-size:13px;text-align:center;margin-bottom:26px}
textarea{width:100%;padding:13px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:13px;font-family:monospace;resize:vertical}
button{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;margin-top:20px}
.error{background:#fff5f5;color:#c53030;padding:12px;border-radius:8px;font-size:13px;margin-bottom:16px;text-align:center}
label{display:block;font-size:13px;color:#4a5568;font-weight:600;margin-bottom:8px}
</style></head><body><div class="card">
<h1>🔐 Testbook Login</h1><p class="sub">Token daaliye.</p>__ERROR__
<form method="post" action="/login"><label>Access Token</label>
<textarea name="token" rows="6" required autofocus></textarea>
<button type="submit">Login →</button></form></div></body></html>"""

# ---------- Routes ----------
@app.get("/health")
async def health(): return {"status":"ok","version":"38.0.0"}

@app.get("/", response_class=HTMLResponse)
async def root(error: Optional[str] = None, session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    if get_token(session_cookie): return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(LOGIN_HTML.replace("__ERROR__", '<div class="error">Session expired.</div>' if error == "session" else ""))

@app.post("/login")
async def login(token: str = Form(...)):
    token = token.strip()
    if not token: return HTMLResponse(LOGIN_HTML.replace("__ERROR__",'<div class="error">Token khali.</div>'), status_code=400)
    if token.lower().startswith("bearer "): token = token[7:].strip()
    if "auth_code=" in token: token = token.split("auth_code=")[1].split("&")[0]
    ok, msg = validate_jwt(token)
    if not ok: return HTMLResponse(LOGIN_HTML.replace("__ERROR__", f'<div class="error">❌ {msg}</div>'), status_code=401)
    if await fetch_stats(token) is None:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__",'<div class="error">❌ Token invalid.</div>'), status_code=401)
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie("tb_session", sign_token(token), httponly=True, samesite="lax", max_age=7*24*3600)
    return resp

@app.get("/logout")
async def logout():
    resp = RedirectResponse("/", status_code=302); resp.delete_cookie("tb_session"); return resp

# ---------- DASHBOARD ----------
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)
    user = get_user_info(token)
    stats = await fetch_stats(token)

    # Try HTML scrape first
    scrape = await scrape_page_for_series(token, "/online-test-series")
    series_map = {}
    for s in scrape["series"] + scrape["dom_series"]:
        sid = s.get("id") or ""
        if sid and sid not in series_map:
            series_map[sid] = s

    # If nothing found, try more endpoints
    if not series_map:
        more = await try_more_endpoints(token)
        for s in more["raw_dumps"]:
            sid = s.get("id") or ""
            if sid and sid not in series_map:
                series_map[sid] = s

    all_series = list(series_map.values())

    stats_html = ""
    if stats:
        stats_html = f"""<div class="stat-row">
        <div class="stat"><div class="num">{stats.get('testsCount',0)}</div><div class="lbl">Tests</div></div>
        <div class="stat"><div class="num">{stats.get('quizzesCount',0)}</div><div class="lbl">Quizzes</div></div>
        <div class="stat"><div class="num">{stats.get('videosCount',0)}</div><div class="lbl">Videos</div></div></div>"""
    paid = " 💎" if user.get("isPaid") else ""

    series_cards = ""
    for s in all_series[:20]:
        total = s.get("totalTests") or 0
        att = s.get("attempted") or 0
        pct = int((att / total) * 100) if total else 0
        slug = s.get("slug") or ""
        series_cards += f"""<div class="series-card">
          <a href="/series?id={quote(s['id'], safe='')}&slug={quote(slug, safe='')}">
            <h3>{s['title']}</h3>
            <div class="progress-row"><span>{att}/{total if total else '—'}</span><span>{pct}%</span></div>
            <div class="progress-bar"><div class="fill" style="width:{pct}%"></div></div>
            <div class="btn-go">Go To Test Series</div>
          </a></div>"""

    hint = ""
    if not all_series:
        hint = f'<div class="empty"><h2>😕 Series nahi mili</h2><p>HTML len: {scrape["html_len"]}, scripts: {len(scrape["scripts_info"])}, dom: {len(scrape["dom_series"])}</p><a href="/debug/probe" class="btn" style="margin-top:12px;">🔍 Full Debug</a></div>'

    body = f"""<div class="container">
    <div class="info-box">✅ <b>Welcome, {user['name']}{paid}!</b><br>{user['email']}</div>
    {stats_html}
    <form class="search-box" method="get" action="/search">
      <input type="text" name="q" placeholder="Search for your Exam" />
      <button type="submit">Search</button></form>
    {f'<div class="section-title">📚 Your Test Series ({len(all_series)})</div><div class="row">{series_cards}</div>' if series_cards else hint}
    </div>"""
    return HTMLResponse(shell("Dashboard", body))

@app.get("/online-test-series", response_class=HTMLResponse)
async def online_series(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)
    scrape = await scrape_page_for_series(token, "/online-test-series")
    series_map = {}
    for s in scrape["series"] + scrape["dom_series"]:
        sid = s.get("id") or ""
        if sid and sid not in series_map: series_map[sid] = s
    all_series = list(series_map.values())
    cards = "".join(
        f'<div class="card"><a href="/series?id={quote(s["id"], safe="")}">'
        f'<h3>{s["title"]}</h3><span class="badge">Open →</span></a></div>' for s in all_series)
    body = f'<div class="container"><a href="/dashboard" class="back-btn">← Back</a>' \
           f'<div class="info-box"><b>📝 All Series ({len(all_series)})</b></div>' \
           f'<div class="row">{cards if cards else "<div class=empty><h2>No series</h2></div>"}</div></div>'
    return HTMLResponse(shell("Series", body))

@app.get("/search", response_class=HTMLResponse)
async def search_page(q: str = Query(""), session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)
    results = []
    if q:
        scrape = await scrape_page_for_series(token, "/online-test-series")
        ql = q.lower()
        for s in scrape["series"] + scrape["dom_series"]:
            if ql in (s.get("title") or "").lower():
                results.append(s)
    cards = "".join(f'<div class="card"><a href="/series?id={quote(r["id"], safe="")}"><h3>{r["title"]}</h3></a></div>' for r in results)
    body = f'''<div class="container"><a href="/dashboard" class="back-btn">← Back</a>
    <form class="search-box" method="get" action="/search">
    <input type="text" name="q" value="{q}" placeholder="Search...">
    <button type="submit">Search</button></form>
    <div class="section-title">{len(results)} results</div><div class="row">{cards}</div></div>'''
    return HTMLResponse(shell("Search", body))

@app.get("/series", response_class=HTMLResponse)
async def series_page(id: str = Query(...), slug: str = Query(""),
                      session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)
    result = await fetch_series_tests(token, id, slug)
    tests = result["tests"]
    title = slug.replace("-", " ").title() if slug else "Test Series"
    cards = "".join(
        f'<div class="card"><a href="/test?id={quote(t["id"], safe="")}&name={quote(t["title"], safe="")}">'
        f'<h3>{t["title"]}</h3><p>{t["questionCount"]} Qs · {t["duration"]} min</p>'
        f'<span class="badge green">Start →</span></a></div>' for t in tests)
    body = f"""<div class="container"><a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>📚 {title}</b><br>Total {len(tests)} tests</div>
    <div class="section-title">📝 Tests</div>
    <div class="row">{cards if cards else '<div class="empty"><h2>No tests</h2></div>'}</div>
    </div>"""
    return HTMLResponse(shell(title, body))

@app.get("/test", response_class=HTMLResponse)
async def test_page(id: str = Query(...), name: str = Query(""),
                    session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)
    title = name or "Test"
    body = f"""<div id="loading" class="loading-box"><div class="spinner"></div><p>Loading...</p></div>
    <div id="quiz"></div>
    <script>
    fetch('/api/test-questions?id=' + encodeURIComponent({json.dumps(id)}))
    .then(r=>r.json()).then(data=>{{
      document.getElementById('loading').style.display='none';
      const box=document.getElementById('quiz');
      if(!data.questions||data.questions.length===0){{
        box.innerHTML='<div class="empty"><h2>😕 Questions load nahi hue</h2><p>'+(data.error||'')+'</p></div>';
        return;
      }}
      renderQuiz(data.questions,data.test_info||{{}});
    }});
    function renderQuiz(questions,info){{
      window.__answers={{}};window.__questions=questions;window.__current=0;window.__lang='en';
      window.__timeLeft=(info.duration||30)*60;window.__timerInterval=null;
      let html='<div class="container" style="padding:0;max-width:100%">';
      html+='<div class="tb-header"><span class="q-num-big" id="qNum">1.</span>'+
        '<div class="q-stats"><div class="q-stat"><span class="lbl">Marks</span><span class="val" id="qMarks">+'+(questions[0].posMarks||4)+' / -'+(questions[0].negMarks||1)+'</span></div>'+
        '<div class="q-stat"><span class="lbl">Time</span><span class="val" id="qTime">00:00</span></div></div>'+
        '<div class="timer-box" id="mainTimer">--:--</div>'+
        '<select class="lang-select" onchange="switchLang(this.value)"><option value="en">English</option><option value="hi">हिंदी</option></select></div>';
      html+='<div class="progress-bar"><div class="fill" id="progressFill" style="width:0%"></div></div>';
      html+='<div class="q-indicators" id="indicators"></div>';
      html+='<div class="tb-question" id="questionArea"></div>';
      html+='<div class="tb-nav"><button onclick="clearResponse()">Clear</button><button onclick="prevQuestion()">← Prev</button>'+
        '<button class="btn-save" onclick="saveAndNext()">Save & Next →</button>'+
        '<button class="btn-submit" onclick="submitQuiz()">Submit</button></div></div>';
      document.getElementById('quiz').innerHTML=html;
      renderCurrent();startTimer();
    }}
    function renderCurrent(){{
      const q=window.__questions[window.__current];const lang=window.__lang;
      const qText=(lang==='hi'&&q.text_hi)?q.text_hi:(q.text_en||q.text);
      const qOpts=(lang==='hi'&&q.options_hi&&q.options_hi.length)?q.options_hi:(q.options_en||q.options);
      document.getElementById('qNum').textContent=(window.__current+1)+'.';
      document.getElementById('qMarks').innerHTML='+'+(q.posMarks||4)+' / -'+(q.negMarks||1);
      let html='<div class="q-text">'+esc(qText)+'</div>';
      qOpts.forEach((opt,j)=>{{
        const sel=window.__answers[window.__current]===j?'selected':'';
        html+='<div class="tb-opt '+sel+'" onclick="pick('+j+', this)"><div class="radio"></div><div class="opt-text">'+esc(opt)+'</div></div>';
      }});
      document.getElementById('questionArea').innerHTML=html;
      renderIndicators();updateProgress();
    }}
    function renderIndicators(){{
      let h='';
      for(let i=0;i<window.__questions.length;i++){{
        const cls=(i===window.__current?'current ':'')+(window.__answers[i]!==undefined?'answered ':'');
        h+='<div class="q-indicator '+cls+'" onclick="jump('+i+')">'+(i+1)+'</div>';
      }}
      document.getElementById('indicators').innerHTML=h;
    }}
    function pick(j,el){{window.__answers[window.__current]=j;
      document.querySelectorAll('.tb-opt').forEach(e=>e.classList.remove('selected'));
      el.classList.add('selected');renderIndicators();updateProgress();}}
    function clearResponse(){{delete window.__answers[window.__current];renderCurrent();}}
    function saveAndNext(){{if(window.__current<window.__questions.length-1){{window.__current++;renderCurrent();window.scrollTo({{top:0}});}}}}
    function prevQuestion(){{if(window.__current>0){{window.__current--;renderCurrent();window.scrollTo({{top:0}});}}}}
    function jump(i){{window.__current=i;renderCurrent();window.scrollTo({{top:0}});}}
    function switchLang(l){{window.__lang=l;renderCurrent();}}
    function updateProgress(){{document.getElementById('progressFill').style.width=(Object.keys(window.__answers).length/window.__questions.length)*100+'%';}}
    function startTimer(){{updateTimer();window.__timerInterval=setInterval(()=>{{if(window.__timeLeft<=0){{clearInterval(window.__timerInterval);submitQuiz();return;}}window.__timeLeft--;updateTimer();}},1000);}}
    function updateTimer(){{const t=window.__timeLeft,h=Math.floor(t/3600),m=Math.floor((t%3600)/60),s=t%60;
      const p=n=>String(n).padStart(2,'0');
      document.getElementById('mainTimer').textContent=(h>0?p(h)+':':'')+p(m)+':'+p(s);}}
    function submitQuiz(){{if(!confirm('Submit?'))return;
      clearInterval(window.__timerInterval);
      const ans=window.__answers,qs=window.__questions;
      let att=Object.keys(ans).length,cor=0,wr=0,sc=0;
      qs.forEach((q,i)=>{{if(q.correctIndex>=0){{sc++;if(ans[i]===q.correctIndex)cor++;else if(ans[i]!==undefined)wr++;}}}});
      const rb=document.createElement('div');rb.className='result-box';
      if(sc===0)rb.innerHTML='<div class="lbl">Submitted ✅</div><div class="score">'+att+' / '+qs.length+'</div><div class="lbl">Attempted</div>';
      else rb.innerHTML='<div class="lbl">Your Score</div><div class="score">'+cor+' / '+qs.length+'</div><div class="lbl">Attempted: '+att+' · Correct: '+cor+' · Wrong: '+wr+'</div>';
      document.getElementById('quiz').innerHTML='';document.getElementById('quiz').appendChild(rb);
      window.scrollTo({{top:0,behavior:'smooth'}});}}
    function esc(s){{if(s==null)return '';return String(s).replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));}}
    </script>"""
    return HTMLResponse(shell(title, body))

@app.get("/api/test-questions")
async def api_test_questions(id: str = Query(...),
                             session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return JSONResponse({"error": "not logged in", "questions": []}, status_code=401)
    try:
        result = await asyncio.wait_for(fetch_questions(token, id), timeout=25.0)
        return {"questions": result["questions"], "count": len(result["questions"]),
                "test_info": result.get("test_info"), "error": result.get("error")}
    except Exception as e:
        return {"questions": [], "error": str(e)}

# ---------- FULL DEBUG ----------
@app.get("/debug/probe", response_class=HTMLResponse)
async def probe(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)

    lines = []
    user = get_user_info(token)
    lines.append(f"User: {user.get('name')} | isPaid: {user.get('isPaid')}")
    lines.append("")

    # --- Approach 1: HTML scrape ---
    lines.append("=== APPROACH 1: HTML SCRAPE of /online-test-series ===")
    scrape = await scrape_page_for_series(token, "/online-test-series")
    lines.append(f"HTML length: {scrape['html_len']}")
    lines.append(f"Script tags with JSON/state: {len(scrape['scripts_info'])}")
    for si in scrape["scripts_info"][:10]:
        lines.append(f"  <script id='{si['id']}' type='{si['type']}'> len={si['len']}")
    lines.append(f"Series from JSON: {len(scrape['series'])}")
    for s in scrape["series"][:10]:
        lines.append(f"  → {s['title'][:60]} | {s['attempted']}/{s['totalTests']} | id={s['id'][:16]}")
    lines.append(f"Series from DOM: {len(scrape['dom_series'])}")
    for s in scrape["dom_series"][:10]:
        lines.append(f"  → {s['title'][:60]} | href={s['href'][:60]}")
    lines.append("")

    # --- Approach 2: more endpoints ---
    lines.append("=== APPROACH 2: MORE ENDPOINTS ===")
    more = await try_more_endpoints(token)
    lines.append(f"Hits: {len(more['hits'])}")
    for h in more["hits"][:15]:
        lines.append(f"  [{h['series_count']} series] {h['url']}")
        lines.append(f"      keys: {h['keys']}")
        if h['series_count'] > 0:
            lines.append(f"      preview: {h['preview'][:200]}")
    lines.append("")

    # --- Approach 3: Fetch /online-test-series HTML and dump raw JSON in scripts ---
    lines.append("=== APPROACH 3: RAW SCRIPT DUMP ===")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=20) as c:
            r = await c.get(BASE_URL + "/online-test-series", headers=tb_headers(token, html_mode=True))
            soup = BeautifulSoup(r.text, "html.parser")
            for sc in soup.find_all("script"):
                txt = sc.string or ""
                if len(txt) > 500:
                    sid = sc.get("id") or "(no-id)"
                    stype = sc.get("type") or "(no-type)"
                    lines.append(f"\n  Script [{sid}] type={stype} len={len(txt)}")
                    lines.append(f"  First 300: {txt[:300]}")
    except Exception as e:
        lines.append(f"  ERR: {e}")

    body = f"""<div class="container"><a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box">🔍 Full Debug — HTML scrape + more endpoints + raw scripts</div>
    <div class="debug">{chr(10).join(lines)}</div></div>"""
    return HTMLResponse(shell("Debug", body))
