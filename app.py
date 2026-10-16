# app.py
import os
import json
import time
import hmac
import base64
import hashlib
import httpx
from fastapi import FastAPI, Form, Cookie, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Optional, List, Dict, Any
from urllib.parse import quote

app = FastAPI(title="Testbook Mirror", version="15.0.0")

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
    return {"name": p.get("name") or "User", "email": p.get("email") or ""}

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
        async with httpx.AsyncClient(timeout=15.0) as client:
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
        async with httpx.AsyncClient(timeout=20.0) as client:
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

# ---------- Test finder ----------
def find_tests_loose(node: Any, out: List[dict], depth: int = 0):
    if depth > 10:
        return
    if isinstance(node, list):
        for x in node:
            find_tests_loose(x, out, depth + 1)
    elif isinstance(node, dict):
        keys = set(node.keys())
        has_id = "id" in keys or "_id" in keys
        has_name = "name" in keys or "title" in keys
        test_hints = keys & {"questionCount", "totalQuestions", "questionsCount",
                             "duration", "totalTime", "totalMarks", "marks",
                             "questions", "maxMarks", "time", "totalQuestionsCount",
                             "testType", "test_type", "attempted", "isAttempted"}
        if has_id and has_name and test_hints:
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
            "title": str(t.get("name") or t.get("title") or "Test"),
            "questionCount": (t.get("questionCount") or t.get("totalQuestions")
                              or t.get("questionsCount") or t.get("questions")
                              or t.get("totalQuestionsCount") or 0),
            "duration": t.get("duration") or t.get("totalTime") or t.get("time") or 0,
            "totalMarks": t.get("totalMarks") or t.get("marks") or t.get("maxMarks") or 0,
            "testType": t.get("testType") or t.get("test_type") or "",
        })
    return result

# ---------- Subsection test endpoint candidates ----------
def subsection_endpoints(series_id: str, section_id: str, subsection_id: str) -> List[str]:
    s, sec, sub = quote(series_id, safe=""), quote(section_id, safe=""), quote(subsection_id, safe="")
    return [
        # Nested paths
        f"{API_BASE}/api/v2_1/test-series/{s}/sections/{sec}/subsections/{sub}/tests",
        f"{API_BASE}/api/v2_1/test-series/{s}/section/{sec}/subsection/{sub}/tests",
        f"{API_BASE}/api/v2_1/test-series/{s}/subsections/{sub}/tests",
        f"{API_BASE}/api/v2_1/test-series/{s}/subsection/{sub}/tests",
        f"{API_BASE}/api/v2_1/subsections/{sub}/tests",
        f"{API_BASE}/api/v2_1/subsection/{sub}/tests",
        f"{API_BASE}/api/v2_1/sections/{sec}/subsections/{sub}/tests",
        f"{API_BASE}/api/v2_1/section/{sec}/tests",
        f"{API_BASE}/api/v2_1/sections/{sec}/tests",
        # Query strings on series
        f"{API_BASE}/api/v2_1/test-series/{s}/tests?sectionId={sec}&subsectionId={sub}",
        f"{API_BASE}/api/v2_1/test-series/{s}/tests?sectionId={sec}",
        f"{API_BASE}/api/v2_1/test-series/{s}/tests?subsectionId={sub}",
        f"{API_BASE}/api/v2_1/test-series/{s}/tests?branchId={sub}",
        f"{API_BASE}/api/v2_1/test-series/{s}/tests",
        f"{API_BASE}/api/v2_1/test-series/{s}/test-list?sectionId={sec}&subsectionId={sub}",
        # Query strings on global tests
        f"{API_BASE}/api/v2_1/tests?seriesId={s}&sectionId={sec}&subsectionId={sub}",
        f"{API_BASE}/api/v2_1/tests?testSeriesId={s}&sectionId={sec}&subsectionId={sub}",
        f"{API_BASE}/api/v2_1/tests?testSeriesId={s}&subsectionId={sub}",
        # v2 versions
        f"{API_BASE}/api/v2/test-series/{s}/tests?sectionId={sec}&subsectionId={sub}",
        f"{API_BASE}/api/v2/subsections/{sub}/tests",
    ]

async def try_endpoints_for_tests(token: str, series_id: str, section_id: str, subsection_id: str) -> tuple[List[Dict], str]:
    """Try all endpoints for a subsection; return (tests, endpoint_used)."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        for url in subsection_endpoints(series_id, section_id, subsection_id):
            full = f"{url}{'&' if '?' in url else '?'}auth_code={quote(token, safe='')}&language=english"
            try:
                r = await client.get(full, headers=tb_headers(token))
                if r.status_code != 200:
                    continue
                j = r.json()
                if not isinstance(j, dict) or not j.get("success"):
                    continue
                raw: List[dict] = []
                find_tests_loose(j, raw)
                tests = normalize_tests(raw)
                if tests:
                    return tests, url
            except Exception:
                continue
    return [], "none"

# ---------- Fetch all tests for series ----------
async def fetch_series_tests(token: str, series_id: str) -> tuple[List[Dict], Dict, Optional[Dict]]:
    url = f"{API_BASE}/api/v2_1/test-series/{quote(series_id, safe='')}?auth_code={quote(token, safe='')}&language=english"
    debug = {"status": 0, "sections": 0, "subsections": 0, "endpoints_tried": 0, "matched": None}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            debug["status"] = r.status_code
            if r.status_code != 200:
                return [], debug, None
            j = r.json()
            if not j.get("success"):
                return [], debug, None
            data = j.get("data", {})
            details = data.get("details", {}) if isinstance(data, dict) else {}

            series_info = {
                "id": series_id,
                "title": details.get("name") or "Test Series",
                "description": details.get("description") or "",
            }

            all_tests: List[Dict] = []
            sections = details.get("sections", [])
            debug["sections"] = len(sections) if isinstance(sections, list) else 0

            for sec in sections:
                sec_id = sec.get("id", "")
                for sub in sec.get("subsections", []):
                    sub_id = sub.get("id", "")
                    debug["subsections"] += 1
                    # First check if inline
                    inner = sub.get("tests")
                    if isinstance(inner, list) and inner:
                        for t in inner:
                            if isinstance(t, dict):
                                all_tests.append(t)
                        continue
                    # Otherwise probe endpoints
                    tests, used = await try_endpoints_for_tests(token, series_id, sec_id, sub_id)
                    debug["endpoints_tried"] += 1
                    if tests:
                        debug["matched"] = used
                        all_tests.extend(tests)
                    # Stop probing if we found a working endpoint — use same one for rest
                    if debug.get("matched"):
                        # Reuse matched endpoint for remaining subsections by extracting pattern
                        pass

            normalized = normalize_tests(all_tests)
            debug["tests_found"] = len(normalized)
            return normalized, debug, series_info
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
.topbar .nav a:hover{background:rgba(255,255,255,.32)}
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
.badge.orange{background:#fed7aa;color:#c2410c}
.row{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.empty{text-align:center;padding:40px 20px;color:#a0aec0}
.empty h2{font-size:18px;margin-bottom:8px;color:#4a5568}
.btn{display:inline-block;padding:11px 20px;background:#4f46e5;color:#fff;
border:none;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;
cursor:pointer;text-align:center}
.btn:hover{background:#4338ca}
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
async def health(): return {"status":"ok","version":"15.0.0"}

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
    greeting = f'<div class="info-box">✅ <b>Welcome, {user["name"]}!</b><br>{user["email"]}</div>'

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
async def series_page(id: str = Query(...), slug: str = Query(""),
                      debug: int = 0,
                      session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    tests, dbg, info = await fetch_series_tests(token, id)
    title = (info or {}).get("title") or "Test Series"

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">{json.dumps(dbg, indent=2, ensure_ascii=False)[:2000]}</div>'

    if tests:
        cards = "".join(
            f'<div class="card"><a href="/test?id={quote(t["id"], safe="")}&name={quote(t["title"], safe="")}">'
            f'<h3>{t["title"]}</h3>'
            f'<p>{f"📝 {t[chr(113)+chr(117)+chr(101)+chr(115)+chr(116)+chr(105)+chr(111)+chr(110)+chr(67)+chr(111)+chr(117)+chr(110)+chr(116)]} Qs" if t.get("questionCount") else ""}'
            f'{f" · ⏱ {t[chr(100)+chr(117)+chr(114)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)]} min" if t.get("duration") else ""}'
            f'{f" · 🎯 {t[chr(116)+chr(111)+chr(116)+chr(97)+chr(108)+chr(77)+chr(97)+chr(114)+chr(107)+chr(115)]} marks" if t.get("totalMarks") else ""}</p>'
            f'<span class="badge green">Open Test →</span></a></div>'
            for t in tests
        )
        body = f"""<a href="/dashboard" class="back-btn">← Back</a>
        <div class="info-box"><b>📚 {title}</b><br>Total {len(tests)} tests</div>
        <div class="section-title">📝 Tests ({len(tests)})</div>
        <div class="row">{cards}</div>
        {debug_html}"""
    else:
        body = f"""<a href="/dashboard" class="back-btn">← Back</a>
        <div class="info-box"><b>📚 {title}</b></div>
        <div class="empty">
          <h2>Is series me tests nahi mil rahe</h2>
          <p>Debug page check karein: <a href="/debug/probe" class="btn" style="margin-top:10px;">🔍 Debug</a></p>
        </div>
        {debug_html}"""
    return HTMLResponse(shell(title, body))

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

# ---------- Debug: try all subsection endpoints ----------
@app.get("/debug/probe", response_class=HTMLResponse)
async def probe(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    lines = []
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            # Get first series
            r = await client.get(f"{SERIES_LIST_API}?exam=rrb-group-d&auth_code={quote(token,safe='')}", headers=tb_headers(token))
            j = r.json()
            ts = j.get("data",{}).get("testSeries",[])
            if not ts:
                lines.append("No series found")
            else:
                sid = ts[0]["details"]["id"]
                lines.append(f"Series: {ts[0]['details']['name']}")
                lines.append(f"ID: {sid}")

                # Get series detail
                r2 = await client.get(f"{API_BASE}/api/v2_1/test-series/{sid}?auth_code={quote(token,safe='')}", headers=tb_headers(token))
                data = r2.json().get("data", {})
                details = data.get("details", {})
                sections = details.get("sections", [])

                # Take first section + subsection
                if sections:
                    sec = sections[0]
                    sec_id = sec.get("id")
                    subs = sec.get("subsections", [])
                    if subs:
                        sub = subs[0]
                        sub_id = sub.get("id")
                        lines.append(f"\nTesting section={sec.get('name')} ({sec_id})")
                        lines.append(f"Testing subsection={sub.get('name')} ({sub_id})")
                        lines.append(f"\nProbing {len(subsection_endpoints(sid, sec_id, sub_id))} endpoints...\n")

                        # Try all endpoints for this subsection
                        async with httpx.AsyncClient(timeout=8.0) as c2:
                            for url in subsection_endpoints(sid, sec_id, sub_id):
                                full = f"{url}{'&' if '?' in url else '?'}auth_code={quote(token,safe='')}&language=english"
                                try:
                                    rr = await c2.get(full, headers=tb_headers(token))
                                    status = rr.status_code
                                    if status == 200:
                                        try:
                                            jj = rr.json()
                                            if jj.get("success"):
                                                raw: List[dict] = []
                                                find_tests_loose(jj, raw)
                                                mark = f"✅ [{status}] tests={len(raw)}"
                                            else:
                                                mark = f"❌ [{status}] success=false"
                                        except Exception:
                                            mark = f"⚠️  [{status}] non-json"
                                    else:
                                        mark = f"❌ [{status}]"
                                    lines.append(f"{mark}  {url}")
                                except Exception as e:
                                    lines.append(f"💥 ERR  {url}  → {str(e)[:60]}")
    except Exception as e:
        lines.append(f"ERR: {e}")

    body = f"""<a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box">Har subsection endpoint probe</div>
    <div class="debug">{chr(10).join(lines)}</div>"""
    return HTMLResponse(shell("Debug", body))
