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
from bs4 import BeautifulSoup
from typing import Optional, List, Dict
from urllib.parse import quote

app = FastAPI(title="Testbook Mirror", version="12.0.0")

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
        "userId": p.get("sub") or "",
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
                    "totalTests": d.get("totalTests") or 0,
                })
            return results
    except Exception as e:
        print("series list error:", e)
        return []

# ---------- Series detail ----------
def find_tests_loose(node, out, depth=0):
    """Loose matcher — id + name, and includes some test-like key."""
    if depth > 10:
        return
    if isinstance(node, list):
        for x in node:
            find_tests_loose(x, out, depth + 1)
    elif isinstance(node, dict):
        keys = set(node.keys())
        has_id = ("id" in keys) or ("_id" in keys)
        has_name = ("name" in keys) or ("title" in keys)
        test_hints = keys & {"questionCount", "totalQuestions", "questionsCount",
                             "duration", "totalTime", "totalMarks", "marks",
                             "questions", "totalMarks", "testType", "test_type",
                             "maxMarks", "time", "questionsCount", "totalQuestionsCount"}
        # Also accept if object has 'testId' or 'test_id'
        is_test = has_id and has_name and (test_hints or "testType" in keys)
        if is_test:
            out.append(node)
        for v in node.values():
            if isinstance(v, (list, dict)):
                find_tests_loose(v, out, depth + 1)

async def fetch_series_detail(token: str, series_id: str) -> tuple[Optional[Dict], List[Dict], Dict]:
    """Return (series_info, tests, debug)."""
    url = f"{API_BASE}/api/v2_1/test-series/{quote(series_id, safe='')}?auth_code={quote(token, safe='')}&language=english"
    debug = {"url": url, "status": 0, "tests_found": 0, "raw_preview": ""}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            debug["status"] = r.status_code
            if r.status_code != 200:
                debug["error"] = r.text[:300]
                return None, [], debug
            j = r.json()
            if not j.get("success"):
                debug["error"] = json.dumps(j)[:300]
                return None, [], debug

            data = j.get("data", {})
            debug["raw_preview"] = json.dumps(data, ensure_ascii=False)[:1200]

            # Try tests under 'details' key variations
            tests_raw = []
            # 1. Loose walk
            find_tests_loose(data, tests_raw)

            # Also try known keys directly
            for key_path in ("details.tests", "tests", "testList", "test_list",
                             "details.testList", "details.testsList", "details.test",
                             "data.tests"):
                parts = key_path.split(".")
                node = data
                ok = True
                for p in parts:
                    if isinstance(node, dict) and p in node:
                        node = node[p]
                    else:
                        ok = False
                        break
                if ok and isinstance(node, list):
                    for x in node:
                        if isinstance(x, dict):
                            tests_raw.append(x)

            # Normalize
            tests = []
            seen = set()
            for t in tests_raw:
                tid = str(t.get("id") or t.get("_id") or t.get("testId") or "")
                if not tid or tid in seen:
                    continue
                seen.add(tid)
                tests.append({
                    "id": tid,
                    "title": str(t.get("name") or t.get("title") or "Test"),
                    "questionCount": (t.get("questionCount") or t.get("totalQuestions")
                                      or t.get("questionsCount") or t.get("questions") or 0),
                    "duration": t.get("duration") or t.get("totalTime") or t.get("time") or 0,
                    "totalMarks": t.get("totalMarks") or t.get("marks") or t.get("maxMarks") or 0,
                })
            debug["tests_found"] = len(tests)

            # Series info
            details = data.get("details", {}) if isinstance(data, dict) else {}
            series_info = {
                "id": series_id,
                "title": details.get("name") or "Test Series",
                "description": details.get("description") or "",
            }
            return series_info, tests, debug
    except Exception as e:
        debug["error"] = str(e)
        return None, [], debug

# ---------- HTML fallback ----------
async def fetch_series_tests_html(token: str, series_id: str, slug: str) -> tuple[List[Dict], str]:
    """Fetch series page HTML and extract test links."""
    urls_to_try = []
    if slug:
        urls_to_try.append(f"{BASE_URL}/test-series/{slug}")
    urls_to_try.append(f"{BASE_URL}/test-series/{series_id}")

    for url in urls_to_try:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=25.0) as client:
                r = await client.get(url, headers=tb_headers(token, json_accept=False))
            if r.status_code != 200:
                continue
            soup = BeautifulSoup(r.text, "html.parser")
            tests, seen = [], set()
            for a in soup.find_all("a", href=True):
                href = a["href"]
                text = a.get_text(" ", strip=True)
                if not text or len(text) < 4:
                    continue
                # Accept various test URL patterns
                if not any(x in href for x in ("/tests/", "/take-test/", "/attempt/", "/test/")):
                    continue
                absolute = href if href.startswith("http") else BASE_URL + href
                if absolute in seen:
                    continue
                seen.add(absolute)
                # Extract ID from URL
                tid = absolute.rstrip("/").split("/")[-1]
                tests.append({"id": tid, "title": text, "url": absolute,
                              "questionCount": 0, "duration": 0, "totalMarks": 0})
            if tests:
                return tests, f"html:{url}"
        except Exception as e:
            print(f"html err {url}:", e)
    return [], "none"

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
    return HTMLResponse(f"<h1>Error</h1><pre style='white-space:pre-wrap'>{tb}</pre>", status_code=500)

# ---------- CSS ----------
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#f0f4f8;color:#1a202c;min-height:100vh;padding-bottom:90px}
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
.btn:hover{background:#4338ca}
.btn.gray{background:#e2e8f0;color:#4a5568}
.btn.green{background:#10b981;color:#fff}
.floating{position:fixed;bottom:16px;right:16px;display:flex;gap:8px;z-index:99}
.floating a{padding:10px 16px;border-radius:26px;text-decoration:none;
font-size:12px;font-weight:700;color:#fff;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.floating .home{background:#4f46e5}
.floating .out{background:#dc2626}
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
<div class="floating"><a href="/dashboard" class="home">🏠 Home</a>
<a href="/logout" class="out">Logout</a></div>
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
async def health(): return {"status":"ok","version":"12.0.0"}

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
            f'<div class="card"><a href="/series?id={quote(item["id"], safe="")}&slug={quote(item.get("slug","") or "", safe="")}">'
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

    info, tests, dbg = await fetch_series_detail(token, id)
    title = (info or {}).get("title") or "Test Series"

    # Fallback: HTML scrape
    html_src = "none"
    if not tests:
        tests, html_src = await fetch_series_tests_html(token, id, slug)

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">API: {json.dumps(dbg, indent=2, ensure_ascii=False)[:2500]}\n\nHTML src: {html_src}\n\nTESTS:\n{json.dumps(tests[:10], indent=2, ensure_ascii=False)}</div>'

    if tests:
        cards = "".join(
            f'<div class="card"><a href="/test?id={quote(t["id"], safe="")}&name={quote(t["title"], safe="")}">'
            f'<h3>{t["title"]}</h3>'
            f'<p>{f"📝 {t[chr(113)+chr(117)+chr(101)+chr(115)+chr(116)+chr(105)+chr(111)+chr(110)+chr(67)+chr(111)+chr(117)+chr(110)+chr(116)]} Qs" if t.get("questionCount") else ""}'
            f'{f" · ⏱ {t[chr(100)+chr(117)+chr(114)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)]} min" if t.get("duration") else ""}</p>'
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
          <p>ID: <code>{id}</code></p>
          <br>
          <a href="/series?id={quote(id,safe='')}&slug={quote(slug,safe='')}&debug=1" class="btn">🔍 Debug Info</a>
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
    testbook_test_url = f"{BASE_URL}/take-test/{id}"

    body = f"""<a href="javascript:history.back()" class="back-btn">← Back</a>
    <div class="info-box"><b>🎯 {title}</b></div>
    <div class="card">
      <h3>{title}</h3>
      <p>Test ID: <code>{id}</code></p>
      <p>Live test dena Testbook ke app par hi possible hai (kyunki exam real-time hota hai).</p>
    </div>
    <div style="text-align:center;margin-top:24px;">
      <a href="{testbook_test_url}" target="_blank" class="btn green" style="padding:14px 28px;font-size:15px;">
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

    lines = []
    # Fetch series list to get a sample ID
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(f"{SERIES_LIST_API}?exam=rrb-group-d&auth_code={quote(token,safe='')}", headers=tb_headers(token))
            j = r.json()
            ts = j.get("data",{}).get("testSeries",[])
            if ts:
                sample = ts[0]["details"]
                sid = sample["id"]
                sslug = sample.get("slug", "")
                lines.append(f"Sample series: {sample['name']}")
                lines.append(f"ID: {sid}")
                lines.append(f"Slug: {sslug}")
                lines.append("")

                # Fetch full series detail
                r2 = await client.get(f"{API_BASE}/api/v2_1/test-series/{sid}?auth_code={quote(token,safe='')}", headers=tb_headers(token))
                j2 = r2.json()
                data = j2.get("data", {})
                lines.append(f"=== DETAIL DATA (keys: {list(data.keys())}) ===")
                # Dump each top-level key briefly
                for k, v in data.items():
                    if isinstance(v, dict):
                        lines.append(f"\n[{k}] dict keys: {list(v.keys())}")
                    elif isinstance(v, list):
                        lines.append(f"\n[{k}] list len: {len(v)}")
                        if v and isinstance(v[0], dict):
                            lines.append(f"    first item keys: {list(v[0].keys())}")
                    else:
                        lines.append(f"\n[{k}] = {str(v)[:100]}")
                lines.append("")
                lines.append("=== FULL JSON (first 2500 chars) ===")
                lines.append(json.dumps(data, ensure_ascii=False)[:2500])
    except Exception as e:
        lines.append(f"ERR: {e}")

    body = f"""<a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box">Full series detail ka structure</div>
    <div class="debug">{chr(10).join(lines)}</div>"""
    return HTMLResponse(shell("Debug", body))

@app.get("/api/series")
async def api_series(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return JSONResponse({"error":"not logged in"}, status_code=401)
    return {"series": await fetch_series_list(token)}
