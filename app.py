# app.py
import os
import re
import json
import time
import hmac
import base64
import hashlib
import asyncio
import httpx
from fastapi import FastAPI, Form, Cookie, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from bs4 import BeautifulSoup
from typing import Optional, List, Dict, Any
from urllib.parse import quote

app = FastAPI(title="Testbook Mirror", version="22.0.0")

BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

COUNT_API = f"{API_BASE}/api/v2_1/live-panel/count"
SERIES_LIST_API = f"{API_BASE}/api/v2_1/test-series"

# ---------- Token helpers ----------
def sign_token(token: str) -> str:
    data = base64.urlsafe_b64encode(token.encode()).decode()
    sig = hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{data}.{sig}"

def unsign_token(cookie: str) -> Optional[str]:
    try:
        data, sig = cookie.rsplit(".", 1)
        expected = hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(sig, expected):
            return None
        return base64.urlsafe_b64decode(data.encode()).decode()
    except Exception:
        return None

def get_token(session_cookie: Optional[str]) -> Optional[str]:
    if not session_cookie:
        return None
    return unsign_token(session_cookie)

def decode_jwt_payload(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None

def validate_jwt(token: str):
    p = decode_jwt_payload(token)
    if p is None:
        return False, "Token JWT format me nahi hai"
    exp = p.get("exp")
    if exp and isinstance(exp, (int, float)) and exp < time.time():
        return False, "Token expire ho gaya hai"
    if not any(k in p for k in ("sub", "email", "name", "phone")):
        return False, "Token me user info nahi mili"
    return True, "ok"

def get_user_info(token: str) -> dict:
    p = decode_jwt_payload(token) or {}
    return {
        "name": p.get("name") or "User",
        "email": p.get("email") or "",
        "isPaid": p.get("isPaidUser", False),
    }

def tb_headers(token: str, json_accept: bool = True) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*" if json_accept else "text/html,*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Referer": BASE_URL + "/",
        "Origin": BASE_URL,
        "Cookie": f"tb_token={token}",
    }

# ---------- Stats ----------
async def fetch_stats(token: str) -> Optional[dict]:
    url = f"{COUNT_API}?auth_code={quote(token, safe='')}&language=english"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            if r.status_code == 200:
                j = r.json()
                if j.get("success"):
                    return j.get("data", {})
    except Exception as e:
        print("stats error:", e)
    return None

# ---------- Series list ----------
async def fetch_series_list(token: str) -> List[Dict]:
    url = f"{SERIES_LIST_API}?exam=rrb-group-d&auth_code={quote(token, safe='')}&language=english"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            if r.status_code != 200:
                return []
            j = r.json()
            if not j.get("success"):
                return []
            ts = j.get("data", {}).get("testSeries", [])
            results = []
            for item in ts:
                d = item.get("details", {}) if isinstance(item, dict) else {}
                sid = str(d.get("id") or "")
                if not sid:
                    continue
                results.append({
                    "id": sid,
                    "slug": str(d.get("slug") or ""),
                    "title": str(d.get("name") or "Test Series"),
                    "description": str(d.get("description") or "")[:200],
                })
            return results
    except Exception as e:
        print("series list error:", e)
        return []

# ---------- Test finder (strict — skip series/section) ----------
def is_series_obj(o):
    if not isinstance(o, dict): return False
    k = set(o.keys())
    return "branches" in k and "examStages" in k and "target" in k

def is_section_obj(o):
    if not isinstance(o, dict): return False
    k = set(o.keys())
    return "subsections" in k and "superSectionId" in k

def is_test_obj(o):
    if not isinstance(o, dict): return False
    if is_series_obj(o) or is_section_obj(o):
        return False
    k = set(o.keys())
    has_id = "id" in k or "_id" in k or "testId" in k
    has_name = "name" in k or "title" in k or "testName" in k
    test_markers = {
        "questionCount", "totalQuestions", "questionsCount", "numQuestions",
        "duration", "totalTime", "testDuration", "time",
        "totalMarks", "marks", "maxMarks", "correctMarks",
        "questions", "testType", "test_type", "attempted", "isAttempted",
        "difficultyLevel", "isFree", "freeTest", "paidTest",
        "testCategory", "startTime", "endTime", "liveStatus",
        "testName", "testId", "totalQuestionsCount",
    }
    return has_id and has_name and bool(k & test_markers)

def find_tests_loose(node: Any, out: List[dict], depth: int = 0):
    if depth > 12:
        return
    if isinstance(node, list):
        for x in node:
            find_tests_loose(x, out, depth + 1)
    elif isinstance(node, dict):
        if is_test_obj(node):
            out.append(node)
        for v in node.values():
            if isinstance(v, (list, dict)):
                find_tests_loose(v, out, depth + 1)

def normalize_tests(raw: List[dict]) -> List[Dict]:
    seen, result = set(), []
    for t in raw:
        tid = str(t.get("id") or t.get("_id") or t.get("testId") or "")
        if not tid or tid in seen:
            continue
        seen.add(tid)
        result.append({
            "id": tid,
            "title": str(t.get("name") or t.get("title") or t.get("testName") or "Test"),
            "questionCount": (t.get("questionCount") or t.get("totalQuestions")
                              or t.get("questionsCount") or t.get("questions")
                              or t.get("totalQuestionsCount") or t.get("numQuestions") or 0),
            "duration": t.get("duration") or t.get("totalTime") or t.get("time") or t.get("testDuration") or 0,
            "totalMarks": t.get("totalMarks") or t.get("marks") or t.get("maxMarks") or t.get("correctMarks") or 0,
            "isFree": bool(t.get("isFree") or t.get("freeTest") or False),
        })
    return result

# ---------- Main fetch (INLINE-FIRST) ----------
async def fetch_series_tests(token: str, series_id: str) -> tuple[List[Dict], Dict, Optional[Dict]]:
    """
    Priority:
    1. Check if inline tests exist (subscription token se aane chahiye)
    2. If not, probe subsections in parallel
    3. Deduplicate and return
    """
    debug = {"mode": "unknown", "status": 0, "details_keys": [], "inline_count": 0, "probe_count": 0}
    url = f"{API_BASE}/api/v2_1/test-series/{quote(series_id, safe='')}?auth_code={quote(token, safe='')}&language=english"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            debug["status"] = r.status_code
            if r.status_code != 200:
                debug["error"] = f"HTTP {r.status_code}"
                return [], debug, None
            j = r.json()
            if not j.get("success"):
                debug["error"] = "success=false"
                return [], debug, None
            data = j.get("data", {})
            details = data.get("details", {}) if isinstance(data, dict) else {}
            debug["details_keys"] = list(details.keys())[:30]

            series_info = {
                "id": series_id,
                "title": details.get("name") or "Test Series",
                "description": details.get("description") or "",
                "slug": details.get("slug") or "",
            }

            # ⚡ STEP 1: Check inline tests
            raw_inline: List[dict] = []
            find_tests_loose(data, raw_inline)
            inline_tests = normalize_tests(raw_inline)
            debug["inline_count"] = len(inline_tests)

            if inline_tests:
                debug["mode"] = "inline"
                debug["tests_found"] = len(inline_tests)
                return inline_tests, debug, series_info

            # ⚡ STEP 2: Subsections me dhundho — pehle dekho kis subsection me tests hain
            sections = details.get("sections", [])
            pairs_with_counts = []
            for sec in sections:
                for sub in sec.get("subsections", []):
                    free = sub.get("freeTestCount") or 0
                    paid = sub.get("paidTestCount") or 0
                    if free + paid > 0:
                        pairs_with_counts.append({
                            "sec_id": sec.get("id", ""),
                            "sub_id": sub.get("id", ""),
                            "sec_name": sec.get("name", ""),
                            "sub_name": sub.get("name", ""),
                            "free": free, "paid": paid,
                            "total": free + paid,
                        })

            debug["subsections_with_tests"] = len(pairs_with_counts)
            debug["subsections_list"] = [
                {"name": f"{p['sec_name']} / {p['sub_name']}", "free": p["free"], "paid": p["paid"]}
                for p in pairs_with_counts[:15]
            ]

            if not pairs_with_counts:
                debug["mode"] = "no-subsections-with-tests"
                return [], debug, series_info

            # Sort by total tests desc
            pairs_with_counts.sort(key=lambda x: x["total"], reverse=True)

            # ⚡ STEP 3: Try a series-level tests endpoint first (fast path)
            series_level_urls = [
                f"{API_BASE}/api/v2_1/live-panel/test-series/{quote(series_id, safe='')}/tests",
                f"{API_BASE}/api/v2_1/test-series/{quote(series_id, safe='')}/tests",
                f"{API_BASE}/api/v2_1/test-series/{quote(series_id, safe='')}/test-list",
                f"{API_BASE}/api/v2_1/live-panel/test-series/{quote(series_id, safe='')}/test-list",
                f"{API_BASE}/api/v2/test-series/{quote(series_id, safe='')}/tests",
                f"{API_BASE}/api/v2_1/live-panel/tests?testSeriesId={quote(series_id, safe='')}",
                f"{API_BASE}/api/v2_1/tests?testSeriesId={quote(series_id, safe='')}",
            ]
            async def probe_series_level(u):
                full = f"{u}{'&' if '?' in u else '?'}auth_code={quote(token, safe='')}&language=english"
                try:
                    async with httpx.AsyncClient(timeout=6.0) as c:
                        rr = await c.get(full, headers=tb_headers(token))
                        if rr.status_code != 200:
                            return u, []
                        jj = rr.json()
                        if not isinstance(jj, dict) or not jj.get("success"):
                            return u, []
                        rw: List[dict] = []
                        find_tests_loose(jj, rw)
                        return u, normalize_tests(rw)
                except Exception:
                    return u, []

            series_tasks = [probe_series_level(u) for u in series_level_urls]
            series_results = await asyncio.gather(*series_tasks, return_exceptions=True)
            for res in series_results:
                if isinstance(res, Exception):
                    continue
                u, tests = res
                if tests:
                    debug["mode"] = f"series-level:{u}"
                    debug["tests_found"] = len(tests)
                    return tests, debug, series_info

            # ⚡ STEP 4: Probe subsections in parallel (max 10)
            debug["mode"] = "subsection-probe"

            def build_sub_urls(sec_id, sub_id, s_id):
                s = quote(s_id, safe="")
                sec = quote(sec_id, safe="")
                sub = quote(sub_id, safe="")
                urls = []
                for base in (f"{API_BASE}/api/v2_1/live-panel", f"{API_BASE}/api/v2_1", f"{API_BASE}/api/v2"):
                    urls.append(f"{base}/test-series/{s}/sections/{sec}/subsections/{sub}/tests")
                    urls.append(f"{base}/test-series/{s}/subsections/{sub}/tests")
                    urls.append(f"{base}/subsections/{sub}/tests")
                    urls.append(f"{base}/tests?subsectionId={sub}")
                    urls.append(f"{base}/tests?sectionId={sec}&subsectionId={sub}")
                    urls.append(f"{base}/tests?testSeriesId={s}&subsectionId={sub}")
                return urls

            async def probe_sub(p):
                for u in build_sub_urls(p["sec_id"], p["sub_id"], series_id):
                    full = f"{u}{'&' if '?' in u else '?'}auth_code={quote(token, safe='')}&language=english"
                    try:
                        async with httpx.AsyncClient(timeout=4.0) as c:
                            rr = await c.get(full, headers=tb_headers(token))
                            if rr.status_code != 200:
                                continue
                            jj = rr.json()
                            if not isinstance(jj, dict) or not jj.get("success"):
                                continue
                            rw: List[dict] = []
                            find_tests_loose(jj, rw)
                            if rw:
                                return normalize_tests(rw), u
                    except Exception:
                        continue
                return [], "none"

            # Probe top subsections in parallel (up to 10)
            top_subs = pairs_with_counts[:10]
            async def probe_and_return(p):
                tests, winner = await probe_sub(p)
                return {"tests": tests, "winner": winner, "name": f"{p['sec_name']} / {p['sub_name']}"}

            tasks = [probe_and_return(p) for p in top_subs]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            all_tests = []
            winner_url = None
            for res in results:
                if isinstance(res, Exception):
                    continue
                if res["tests"]:
                    all_tests.extend(res["tests"])
                    if not winner_url:
                        winner_url = res["winner"]

            debug["probe_count"] = len(all_tests)
            debug["winner"] = winner_url

            # Deduplicate
            seen = set()
            final = []
            for t in all_tests:
                if t["id"] not in seen:
                    seen.add(t["id"])
                    final.append(t)
            debug["tests_found"] = len(final)
            return final, debug, series_info
    except Exception as e:
        debug["error"] = str(e)
        return [], debug, None

# ---------- Error handlers ----------
@app.exception_handler(StarletteHTTPException)
async def http_exc(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and request.url.path == "/":
        return RedirectResponse("/")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

@app.exception_handler(Exception)
async def all_exc(request: Request, exc: Exception):
    import traceback
    tb = traceback.format_exc()
    print("ERROR:", tb)
    return HTMLResponse(f"<h1>Error</h1><pre>{tb}</pre>", status_code=500)

# ---------- CSS ----------
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#f0f4f8;color:#1a202c;min-height:100vh}
.topbar{background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff;
padding:14px 18px;display:flex;align-items:center;justify-content:space-between;
position:sticky;top:0;z-index:100;box-shadow:0 4px 14px rgba(0,0,0,.15);flex-wrap:wrap;gap:8px}
.topbar h1{font-size:16px;font-weight:700}
.topbar .nav{display:flex;gap:6px;font-size:12px;flex-wrap:wrap}
.topbar .nav a{color:#fff;text-decoration:none;padding:6px 12px;
background:rgba(255,255,255,.18);border-radius:8px;font-weight:600}
.container{max-width:920px;margin:0 auto;padding:18px}
.section-title{font-size:14px;font-weight:700;color:#4a5568;margin:8px 0 14px;
text-transform:uppercase;letter-spacing:.5px}
.card{background:#fff;border-radius:14px;padding:16px;margin-bottom:12px;
box-shadow:0 2px 10px rgba(0,0,0,.06);border-left:4px solid #4f46e5}
.card a{text-decoration:none;color:#1a202c;display:block}
.card h3{font-size:14px;font-weight:700;color:#1a202c;margin-bottom:6px;line-height:1.4}
.card p{font-size:12px;color:#718096;line-height:1.55;margin-top:4px}
.badge{display:inline-block;background:#eef2ff;color:#4f46e5;font-size:10px;
font-weight:700;padding:3px 9px;border-radius:12px;margin-top:8px;
text-transform:uppercase;letter-spacing:.3px}
.badge.green{background:#d1fae5;color:#059669}
.row{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.empty{text-align:center;padding:40px 20px;color:#a0aec0}
.empty h2{font-size:18px;margin-bottom:8px;color:#4a5568}
.btn{display:inline-block;padding:11px 20px;background:#4f46e5;color:#fff;
border:none;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;
cursor:pointer;text-align:center}
.btn.gray{background:#e2e8f0;color:#4a5568}
.btn.green{background:#10b981;color:#fff}
.info-box{background:#eef2ff;border-radius:12px;padding:14px;margin-bottom:16px;
font-size:13px;color:#3730a3;line-height:1.7}
.stat-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.stat{background:#fff;padding:12px 16px;border-radius:12px;
box-shadow:0 2px 8px rgba(0,0,0,.05);flex:1;min-width:110px;text-align:center}
.stat .num{font-size:24px;font-weight:800;color:#4f46e5}
.stat .lbl{font-size:11px;color:#718096;text-transform:uppercase;
letter-spacing:.4px;margin-top:4px}
.debug{background:#1a202c;color:#a0aec0;padding:14px;border-radius:10px;
font-family:monospace;font-size:11px;overflow:auto;max-height:600px;
line-height:1.5;white-space:pre-wrap;word-break:break-word}
.back-btn{display:inline-block;margin-bottom:14px;padding:8px 16px;
background:#e2e8f0;color:#4a5568;border-radius:8px;text-decoration:none;
font-size:13px;font-weight:600}
.spinner{display:inline-block;width:36px;height:36px;border:4px solid #e2e8f0;
border-top-color:#4f46e5;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.loading-box{text-align:center;padding:50px 20px}
.loading-box p{margin-top:16px;color:#718096;font-size:14px}
"""

def shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Testbook Mirror</title><style>{CSS}</style></head><body>
<div class="topbar"><h1>📚 Testbook Mirror</h1>
<div class="nav"><a href="/dashboard">🏠 Home</a>
<a href="/debug/probe">🔍 Debug</a>
<a href="/logout">Logout</a></div></div>
<div class="container">{body}</div>
</body></html>"""

LOGIN_HTML = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login · Testbook Mirror</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;
align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:18px;box-shadow:0 20px 60px rgba(0,0,0,.3);
padding:40px;width:100%;max-width:500px}
h1{color:#1a202c;font-size:22px;text-align:center;margin-bottom:6px}
p.sub{color:#718096;font-size:13px;text-align:center;margin-bottom:26px}
label{display:block;font-size:13px;color:#4a5568;font-weight:600;margin-bottom:8px}
textarea{width:100%;padding:13px;border:1.5px solid #e2e8f0;border-radius:10px;
font-size:13px;font-family:monospace;resize:vertical}
textarea:focus{outline:none;border-color:#667eea}
button{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);
color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;margin-top:20px}
.error{background:#fff5f5;color:#c53030;padding:12px;border-radius:8px;font-size:13px;margin-bottom:16px;text-align:center}
</style></head><body><div class="card">
<h1>🔐 Testbook Login</h1>
<p class="sub">Token daaliye — dashboard par aapki saari test series live aayengi.</p>
__ERROR__
<form method="post" action="/login">
<label>Access Token</label>
<textarea name="token" rows="6" placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." required autofocus></textarea>
<button type="submit">Login →</button></form>
</div></body></html>"""

# ---------- Routes ----------
@app.get("/health")
async def health(): return {"status":"ok","version":"22.0.0"}

@app.get("/", response_class=HTMLResponse)
async def root(error: Optional[str] = None,
               session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    if get_token(session_cookie):
        return RedirectResponse("/dashboard", status_code=302)
    err = '<div class="error">Token expire ho gaya. Dobara login karein.</div>' if error == "session" else ""
    return HTMLResponse(LOGIN_HTML.replace("__ERROR__", err))

@app.post("/login")
async def login(token: str = Form(...)):
    token = token.strip()
    if not token:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__",'<div class="error">Token khali hai.</div>'), status_code=400)
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if "auth_code=" in token:
        token = token.split("auth_code=")[1].split("&")[0]
    ok, msg = validate_jwt(token)
    if not ok:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", f'<div class="error">❌ {msg}</div>'), status_code=401)
    stats = await fetch_stats(token)
    if stats is None:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__",'<div class="error">❌ Token invalid ya expire.</div>'), status_code=401)
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie("tb_session", sign_token(token), httponly=True, samesite="lax", max_age=7*24*3600, secure=False)
    return resp

@app.get("/logout")
async def logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("tb_session")
    return resp

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)
    user = get_user_info(token)
    stats = await fetch_stats(token)
    series = await fetch_series_list(token)

    stats_html = ""
    if stats:
        stats_html = f"""<div class="stat-row">
        <div class="stat"><div class="num">{stats.get('testsCount',0)}</div><div class="lbl">Tests</div></div>
        <div class="stat"><div class="num">{stats.get('quizzesCount',0)}</div><div class="lbl">Quizzes</div></div>
        <div class="stat"><div class="num">{stats.get('videosCount',0)}</div><div class="lbl">Videos</div></div>
        </div>"""
    paid_badge = " 💎" if user.get("isPaid") else ""
    greeting = f'<div class="info-box">✅ <b>Welcome, {user["name"]}{paid_badge}!</b><br>{user["email"]}</div>'

    if series:
        cards = "".join(
            f'<div class="card"><a href="/series?id={quote(item["id"], safe="")}">'
            f'<h3>{item["title"]}</h3>'
            f'{f"<p>{item[chr(100)+chr(101)+chr(115)+chr(99)+chr(114)+chr(105)+chr(112)+chr(116)+chr(105)+chr(111)+chr(110)][:140]}...</p>" if item.get("description") else ""}'
            f'<span class="badge">Open Series →</span></a></div>'
            for item in series
        )
        body = f"""{greeting}{stats_html}
        <div class="section-title">📚 Test Series ({len(series)})</div>
        <div class="row">{cards}</div>"""
    else:
        body = f"""{greeting}{stats_html}
        <div class="empty"><h2>😕 Series list load nahi hui</h2>
        <a href="/debug/probe" class="btn">🔍 Debug</a></div>"""
    return HTMLResponse(shell("Dashboard", body))

# ---------- Series Page ----------
@app.get("/series", response_class=HTMLResponse)
async def series_page(id: str = Query(...),
                      session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)
    title = "Test Series"
    try:
        url = f"{API_BASE}/api/v2_1/test-series/{quote(id, safe='')}?auth_code={quote(token, safe='')}&language=english"
        async with httpx.AsyncClient(timeout=6.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            if r.status_code == 200:
                j = r.json()
                if j.get("success"):
                    title = j.get("data", {}).get("details", {}).get("name") or title
    except Exception:
        pass

    body = f"""<a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>📚 {title}</b></div>
    <div id="loading" class="loading-box">
      <div class="spinner"></div>
      <p>Tests load ho rahe hain...</p>
    </div>
    <div id="results"></div>
    <script>
      fetch('/api/series-tests?id={quote(id, safe="")}')
        .then(r => r.json())
        .then(data => {{
          document.getElementById('loading').style.display = 'none';
          const box = document.getElementById('results');
          if (!data.tests || data.tests.length === 0) {{
            box.innerHTML = '<div class="empty"><h2>😕 Tests load nahi ho paye</h2>' +
              '<p>' + (data.error || 'Koi test nahi mila') + '</p>' +
              '<p style="margin-top:12px;font-size:11px;">mode: ' + (data.mode || '?') +
              ', inline: ' + (data.inline_count || 0) + '</p>' +
              '<a href="/debug/probe" class="btn" style="margin-top:12px;">🔍 Debug</a></div>';
            return;
          }}
          let html = '<div class="section-title">📝 Tests (' + data.tests.length + ')</div><div class="row">';
          for (const t of data.tests) {{
            const meta = [];
            if (t.questionCount) meta.push('📝 ' + t.questionCount + ' Qs');
            if (t.duration) meta.push('⏱ ' + t.duration + ' min');
            if (t.totalMarks) meta.push('🎯 ' + t.totalMarks + ' marks');
            html += '<div class="card"><a href="/test?id=' + encodeURIComponent(t.id) + '&name=' + encodeURIComponent(t.title) + '">' +
              '<h3>' + t.title + '</h3>' +
              '<p>' + meta.join(' · ') + '</p>' +
              '<span class="badge green">Open Test →</span></a></div>';
          }}
          html += '</div>';
          box.innerHTML = html;
        }})
        .catch(e => {{
          document.getElementById('loading').style.display = 'none';
          document.getElementById('results').innerHTML = '<div class="empty"><h2>Error</h2><p>' + e + '</p></div>';
        }});
    </script>"""
    return HTMLResponse(shell(title, body))

# ---------- API: series tests ----------
@app.get("/api/series-tests")
async def api_series_tests(id: str = Query(...),
                           session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return JSONResponse({"error": "not logged in", "tests": []}, status_code=401)
    try:
        tests, debug, info = await asyncio.wait_for(fetch_series_tests(token, id), timeout=50.0)
        return {
            "tests": tests,
            "count": len(tests),
            "mode": debug.get("mode"),
            "inline_count": debug.get("inline_count", 0),
            "probe_count": debug.get("probe_count", 0),
            "error": debug.get("error"),
        }
    except asyncio.TimeoutError:
        return {"tests": [], "error": "Timeout 50s"}
    except Exception as e:
        return {"tests": [], "error": str(e)}

# ---------- Test Page ----------
@app.get("/test", response_class=HTMLResponse)
async def test_page(id: str = Query(...), name: str = Query(""),
                    session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)
    title = name or "Test"
    body = f"""<a href="javascript:history.back()" class="back-btn">← Back</a>
    <div class="info-box"><b>🎯 {title}</b></div>
    <div class="card"><h3>{title}</h3><p>Test ID: <code>{id}</code></p></div>
    <div style="text-align:center;margin-top:24px;">
      <a href="{BASE_URL}/take-test/{id}" target="_blank" class="btn green" style="padding:14px 28px;font-size:15px;">
        🎯 Start Test on Testbook
      </a>
    </div>"""
    return HTMLResponse(shell(title, body))

# ---------- Debug probe ----------
@app.get("/debug/probe", response_class=HTMLResponse)
async def probe(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    user = get_user_info(token)
    lines = []
    lines.append(f"User: {user.get('name')} ({user.get('email')})")
    lines.append(f"isPaidUser: {user.get('isPaid')}")
    lines.append("")

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(f"{SERIES_LIST_API}?exam=rrb-group-d&auth_code={quote(token,safe='')}", headers=tb_headers(token))
            j = r.json()
            ts = j.get("data",{}).get("testSeries",[])
            if not ts:
                lines.append("No series found")
            else:
                sid = ts[0]["details"]["id"]
                lines.append(f"Series: {ts[0]['details']['name']}")
                lines.append(f"ID: {sid}")

                # Fetch series detail
                r2 = await client.get(f"{API_BASE}/api/v2_1/test-series/{sid}?auth_code={quote(token,safe='')}", headers=tb_headers(token))
                data = r2.json().get("data", {})
                details = data.get("details", {})

                # Inline check
                raw: List[dict] = []
                find_tests_loose(data, raw)
                inline_tests = normalize_tests(raw)
                lines.append(f"\n=== INLINE TESTS ===")
                lines.append(f"Found: {len(inline_tests)}")
                for t in inline_tests[:10]:
                    lines.append(f"  → {t['id'][:12]} | {t['title'][:60]} | {t['questionCount']} Qs")

                # Subsections with counts
                lines.append(f"\n=== SUBSECTIONS WITH TESTS ===")
                sections = details.get("sections", [])
                count = 0
                for sec in sections:
                    for sub in sec.get("subsections", []):
                        free = sub.get("freeTestCount", 0)
                        paid = sub.get("paidTestCount", 0)
                        if free + paid > 0:
                            lines.append(f"  [{sec.get('name')}] {sub.get('name')}: free={free}, paid={paid}")
                            count += 1
                lines.append(f"Total: {count} subsections with tests")

                # Try the series-level endpoints directly
                lines.append(f"\n=== SERIES-LEVEL TESTS ENDPOINTS ===")
                series_urls = [
                    f"{API_BASE}/api/v2_1/live-panel/test-series/{sid}/tests",
                    f"{API_BASE}/api/v2_1/test-series/{sid}/tests",
                    f"{API_BASE}/api/v2_1/live-panel/tests?testSeriesId={sid}",
                    f"{API_BASE}/api/v2_1/tests?testSeriesId={sid}",
                ]
                async def try_su(u):
                    full = f"{u}{'&' if '?' in u else '?'}auth_code={quote(token,safe='')}&language=english"
                    try:
                        async with httpx.AsyncClient(timeout=6.0) as c:
                            rr = await c.get(full, headers=tb_headers(token))
                            if rr.status_code != 200:
                                return u, rr.status_code, 0
                            jj = rr.json()
                            if not isinstance(jj, dict) or not jj.get("success"):
                                return u, rr.status_code, 0
                            rw: List[dict] = []
                            find_tests_loose(jj, rw)
                            return u, rr.status_code, len(rw)
                    except Exception as e:
                        return u, 0, 0
                tasks = [try_su(u) for u in series_urls]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, Exception):
                        continue
                    u, st, cnt = res
                    lines.append(f"  [{st}] tests={cnt}  {u}")
    except Exception as e:
        lines.append(f"ERR: {e}")

    body = f"""<a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box">Inline tests check + series-level endpoints</div>
    <div class="debug">{chr(10).join(lines)}</div>"""
    return HTMLResponse(shell("Debug", body))
