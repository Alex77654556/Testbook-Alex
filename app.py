# app.py
import os
import json
import time
import hmac
import base64
import hashlib
import asyncio
import httpx
import html as html_lib
from fastapi import FastAPI, Form, Cookie, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Optional, List, Dict, Any
from urllib.parse import quote

app = FastAPI(title="Testbook Mirror", version="32.0.0")

BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

COUNT_API = f"{API_BASE}/api/v2_1/live-panel/count"
ALL_API = f"{API_BASE}/api/v2_1/live-panel/all"
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
        if not hmac.compare_digest(sig, expected): return None
        return base64.urlsafe_b64decode(data.encode()).decode()
    except Exception: return None

def get_token(session_cookie: Optional[str]) -> Optional[str]:
    if not session_cookie: return None
    return unsign_token(session_cookie)

def decode_jwt_payload(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3: return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception: return None

def validate_jwt(token: str):
    p = decode_jwt_payload(token)
    if p is None: return False, "Token JWT format me nahi hai"
    exp = p.get("exp")
    if exp and isinstance(exp, (int, float)) and exp < time.time():
        return False, "Token expire ho gaya hai"
    if not any(k in p for k in ("sub", "email", "name", "phone")):
        return False, "Token me user info nahi mili"
    return True, "ok"

def get_user_info(token: str) -> dict:
    p = decode_jwt_payload(token) or {}
    return {"name": p.get("name") or "User", "email": p.get("email") or "",
            "isPaid": p.get("isPaidUser", False)}

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

async def fetch_stats(token: str) -> Optional[dict]:
    url = f"{COUNT_API}?auth_code={quote(token, safe='')}&language=english"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            if r.status_code == 200:
                j = r.json()
                if j.get("success"): return j.get("data", {})
    except Exception: pass
    return None

async def fetch_series_list(token: str) -> List[Dict]:
    url = f"{SERIES_LIST_API}?exam=rrb-group-d&auth_code={quote(token, safe='')}&language=english"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            if r.status_code != 200: return []
            j = r.json()
            if not j.get("success"): return []
            ts = j.get("data", {}).get("testSeries", [])
            results = []
            for item in ts:
                d = item.get("details", {}) if isinstance(item, dict) else {}
                sid = str(d.get("id") or "")
                if not sid: continue
                results.append({"id": sid, "title": str(d.get("name") or "Test Series"),
                                "description": str(d.get("description") or "")[:200]})
            return results
    except Exception: return []

def is_series_or_section(o):
    if not isinstance(o, dict): return False
    k = set(o.keys())
    return ("branches" in k and "examStages" in k) or ("subsections" in k and "superSectionId" in k)

def find_all_tests(node, out, depth=0):
    if depth > 15: return
    if isinstance(node, list):
        for x in node: find_all_tests(x, out, depth + 1)
    elif isinstance(node, dict):
        if not is_series_or_section(node):
            keys = set(node.keys())
            if ("id" in keys or "_id" in keys) and ("title" in keys or "name" in keys):
                if keys & {"questionCount", "totalQuestions", "duration", "totalMark", "totalMarks", "testType"}:
                    out.append(node)
        for v in node.values():
            if isinstance(v, (list, dict)): find_all_tests(v, out, depth + 1)

def normalize_tests(raw):
    seen, result = set(), []
    for t in raw:
        tid = str(t.get("id") or t.get("_id") or "")
        if not tid or tid in seen: continue
        seen.add(tid)
        result.append({"id": tid, "title": str(t.get("title") or t.get("name") or "Test"),
                       "questionCount": t.get("questionCount") or 0,
                       "duration": t.get("duration") or 0,
                       "totalMarks": t.get("totalMarks") or t.get("totalMark") or 0,
                       "isFree": bool(t.get("isFree") or False)})
    return result

async def fetch_all_tests_for_series(token: str, series_id: str) -> List[Dict]:
    url = f"{ALL_API}?tsid={quote(series_id, safe='')}&auth_code={quote(token, safe='')}&language=english"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            if r.status_code != 200: return []
            j = r.json()
            if not j.get("success"): return []
            raw = []
            find_all_tests(j.get("data", {}), raw)
            return normalize_tests(raw)
    except Exception: return []

# ---------- Question text cleaner ----------
def _clean(s: str) -> str:
    """Decode HTML entities and clean question text."""
    if not s:
        return ""
    s = str(s)
    # Decode HTML entities multiple times (&amp;nbsp; → &nbsp; → space)
    for _ in range(3):
        new_s = html_lib.unescape(s)
        if new_s == s:
            break
        s = new_s
    s = s.replace("\u00a0", " ").replace("&nbsp;", " ")
    s = s.strip()
    return s

# ---------- Question parser ----------
def extract_questions_from_test_detail(data: dict) -> List[Dict]:
    questions = []
    sections = data.get("sections", [])
    for sec in sections:
        sec_title = sec.get("title", "")
        for q in sec.get("questions", []):
            if not isinstance(q, dict): continue
            qid = q.get("_id") or q.get("id") or ""

            # Prefer English, fallback Hindi
            en = q.get("en") or q.get("hi") or {}
            if not isinstance(en, dict): en = {}
            text = _clean(en.get("value") or en.get("questionText") or "")

            opts_raw = en.get("options") or []
            options = []
            correct_idx = -1
            for i, o in enumerate(opts_raw):
                if isinstance(o, dict):
                    opt_text = _clean(o.get("value") or o.get("text") or "")
                    options.append(opt_text)
                    if o.get("isCorrect") is True or o.get("correct") is True:
                        correct_idx = i
                else:
                    options.append(_clean(str(o)))

            q_correct = q.get("correctAnswer") or q.get("correct")

            questions.append({
                "id": qid,
                "section": sec_title,
                "type": q.get("type", "mcq"),
                "text": text,
                "options": options,
                "posMarks": q.get("posMarks", 4),
                "negMarks": q.get("negMarks", 1),
                "correctIndex": correct_idx,
                "correctAnswer": q_correct,
            })
    return questions

async def fetch_test_questions(token: str, test_id: str) -> Dict:
    s = quote(test_id, safe="")
    url = f"{API_BASE}/api/v2_1/tests/{s}?auth_code={quote(token, safe='')}&language=english"
    result = {"questions": [], "test_info": None, "error": None}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            if r.status_code != 200:
                result["error"] = f"HTTP {r.status_code}"
                return result
            j = r.json()
            if not j.get("success"):
                result["error"] = "success=false"
                return result
            data = j.get("data", {})
            dur = data.get("duration") or 0
            if dur > 1000: dur = dur // 60
            result["test_info"] = {
                "title": data.get("title") or "Test",
                "duration": dur,
                "totalQuestions": sum(len(s.get("questions", [])) for s in data.get("sections", [])),
            }
            result["questions"] = extract_questions_from_test_detail(data)
            return result
    except Exception as e:
        result["error"] = str(e)
        return result

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
/* Quiz UI */
.quiz-header{background:#fff;border-radius:14px;padding:16px;margin-bottom:14px;
box-shadow:0 2px 10px rgba(0,0,0,.06);position:sticky;top:66px;z-index:50}
.quiz-header h2{font-size:15px;font-weight:700;color:#1a202c;margin-bottom:8px}
.quiz-meta{display:flex;justify-content:space-between;font-size:12px;color:#718096;
flex-wrap:wrap;gap:8px}
.timer{font-weight:700;color:#4f46e5}
.q-card{background:#fff;border-radius:14px;padding:18px;margin-bottom:14px;
box-shadow:0 2px 10px rgba(0,0,0,.06);border-top:3px solid #4f46e5}
.q-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.q-num{display:inline-block;background:#4f46e5;color:#fff;font-size:11px;
font-weight:700;padding:4px 10px;border-radius:8px}
.q-marks{font-size:11px;color:#718096}
.q-marks .pos{color:#10b981;font-weight:700}
.q-marks .neg{color:#ef4444;font-weight:700}
.q-text{font-size:15px;line-height:1.65;color:#2d3748;margin-bottom:14px;white-space:pre-wrap;word-break:break-word}
.opt{display:block;padding:13px 16px;background:#f7fafc;border-radius:10px;
margin-bottom:10px;font-size:14px;color:#2d3748;border:2px solid #e2e8f0;
cursor:pointer;transition:all .15s;user-select:none;word-break:break-word}
.opt:hover{border-color:#a5b4fc;background:#f0f4ff}
.opt.selected{border-color:#4f46e5;background:#eef2ff;font-weight:600}
.opt.correct{border-color:#10b981;background:#d1fae5}
.opt.wrong{border-color:#ef4444;background:#fee2e2}
.opts-letter{display:inline-block;width:24px;height:24px;line-height:24px;
text-align:center;background:#e2e8f0;border-radius:50%;font-size:12px;
font-weight:700;margin-right:10px;color:#4a5568}
.opt.selected .opts-letter{background:#4f46e5;color:#fff}
.opt.correct .opts-letter{background:#10b981;color:#fff}
.opt.wrong .opts-letter{background:#ef4444;color:#fff}
.quiz-footer{background:#fff;border-radius:14px;padding:16px;margin-top:18px;
box-shadow:0 2px 10px rgba(0,0,0,.06);display:flex;gap:10px;flex-wrap:wrap;
position:sticky;bottom:14px;z-index:50}
.quiz-footer button{flex:1;min-width:120px;padding:14px;border:none;border-radius:10px;
font-size:14px;font-weight:700;cursor:pointer}
.submit-btn{background:#10b981;color:#fff}
.submit-btn:hover{background:#059669}
.reset-btn{background:#e2e8f0;color:#4a5568}
.reset-btn:hover{background:#cbd5e0}
.result-box{background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff;
padding:24px;border-radius:14px;text-align:center;margin-bottom:18px}
.result-box .score{font-size:42px;font-weight:900;margin:8px 0}
.result-box .lbl{font-size:13px;opacity:.9}
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
async def health(): return {"status":"ok","version":"32.0.0"}

@app.get("/", response_class=HTMLResponse)
async def root(error: Optional[str] = None,
               session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    if get_token(session_cookie): return RedirectResponse("/dashboard", status_code=302)
    err = '<div class="error">Token expire ho gaya. Dobara login karein.</div>' if error == "session" else ""
    return HTMLResponse(LOGIN_HTML.replace("__ERROR__", err))

@app.post("/login")
async def login(token: str = Form(...)):
    token = token.strip()
    if not token:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__",'<div class="error">Token khali hai.</div>'), status_code=400)
    if token.lower().startswith("bearer "): token = token[7:].strip()
    if "auth_code=" in token: token = token.split("auth_code=")[1].split("&")[0]
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
    if not token: return RedirectResponse("/", status_code=302)
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

@app.get("/series", response_class=HTMLResponse)
async def series_page(id: str = Query(...),
                      session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)
    title = "Test Series"
    try:
        url = f"{API_BASE}/api/v2_1/test-series/{quote(id, safe='')}?auth_code={quote(token, safe='')}&language=english"
        async with httpx.AsyncClient(timeout=6.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            if r.status_code == 200:
                j = r.json()
                if j.get("success"):
                    title = j.get("data", {}).get("details", {}).get("name") or title
    except Exception: pass

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
            box.innerHTML = '<div class="empty"><h2>😕 Tests nahi mile</h2></div>';
            return;
          }}
          let html = '<div class="section-title">📝 Tests (' + data.tests.length + ')</div><div class="row">';
          for (const t of data.tests) {{
            const meta = [];
            if (t.questionCount) meta.push('📝 ' + t.questionCount + ' Qs');
            if (t.duration) meta.push('⏱ ' + t.duration + ' min');
            if (t.totalMarks) meta.push('🎯 ' + t.totalMarks + ' marks');
            html += '<div class="card"><a href="/test?id=' + encodeURIComponent(t.id) + '&name=' + encodeURIComponent(t.title) + '">' +
              '<h3>' + t.title + '</h3><p>' + meta.join(' · ') + '</p>' +
              '<span class="badge green">Start Test →</span></a></div>';
          }}
          html += '</div>';
          box.innerHTML = html;
        }});
    </script>"""
    return HTMLResponse(shell(title, body))

@app.get("/api/series-tests")
async def api_series_tests(id: str = Query(...),
                           session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return JSONResponse({"error": "not logged in", "tests": []}, status_code=401)
    try:
        tests = await asyncio.wait_for(fetch_all_tests_for_series(token, id), timeout=30.0)
        return {"tests": tests, "count": len(tests)}
    except Exception as e:
        return {"tests": [], "error": str(e)}

# ---------- TEST PAGE with quiz UI ----------
@app.get("/test", response_class=HTMLResponse)
async def test_page(id: str = Query(...), name: str = Query(""),
                    session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)
    title = name or "Test"
    body = f"""<a href="javascript:history.back()" class="back-btn">← Back</a>
    <div class="info-box"><b>🎯 {title}</b></div>
    <div id="loading" class="loading-box">
      <div class="spinner"></div>
      <p>Questions load ho rahe hain...</p>
    </div>
    <div id="quiz"></div>
    <script>
      fetch('/api/test-questions?id=' + encodeURIComponent({json.dumps(id)}))
        .then(r => r.json())
        .then(data => {{
          document.getElementById('loading').style.display = 'none';
          const box = document.getElementById('quiz');
          if (!data.questions || data.questions.length === 0) {{
            box.innerHTML = '<div class="empty"><h2>😕 Questions load nahi ho paye</h2>' +
              '<p>' + (data.error || 'Is test ka question data API se nahi mila') + '</p>' +
              '<a href="/debug/probe" class="btn" style="margin-top:12px;">🔍 Debug</a></div>';
            return;
          }}
          renderQuiz(data.questions, data.test_info || {{}});
        }});

      function renderQuiz(questions, info) {{
        window.__answers = {{}}; window.__questions = questions;
        const totalQs = questions.length;
        const totalMarks = questions.reduce((s, q) => s + (q.posMarks || 4), 0);

        let html = '<div class="quiz-header">' +
          '<h2>' + {json.dumps(title)} + '</h2>' +
          '<div class="quiz-meta">' +
          '<span>📝 ' + totalQs + ' Qs · 🎯 ' + totalMarks + ' marks</span>' +
          '<span class="timer" id="answered">Answered: 0 / ' + totalQs + '</span>' +
          '</div></div>';

        questions.forEach((q, i) => {{
          html += '<div class="q-card">' +
            '<div class="q-header">' +
            '<span class="q-num">Q' + (i+1) + '</span>' +
            '<span class="q-marks">' +
            '<span class="pos">+' + (q.posMarks || 4) + '</span> / ' +
            '<span class="neg">-' + (q.negMarks || 1) + '</span>' +
            '</span></div>' +
            '<div class="q-text">' + escapeHtml(q.text) + '</div>';
          const letters = ['A','B','C','D','E','F','G','H'];
          (q.options || []).forEach((opt, j) => {{
            html += '<div class="opt" data-q="' + i + '" data-o="' + j + '" ' +
              'onclick="selectOption(this,' + i + ',' + j + ')">' +
              '<span class="opts-letter">' + letters[j] + '</span>' + escapeHtml(opt) + '</div>';
          }});
          html += '</div>';
        }});

        html += '<div class="quiz-footer">' +
          '<button class="submit-btn" onclick="submitQuiz(' + totalQs + ')">✅ Submit Test</button>' +
          '<button class="reset-btn" onclick="window.location.reload()">🔄 Reset</button>' +
          '</div>';

        document.getElementById('quiz').innerHTML = html;
      }}

      function selectOption(el, q, o) {{
        document.querySelectorAll('.opt[data-q="' + q + '"]').forEach(a => a.classList.remove('selected'));
        el.classList.add('selected');
        window.__answers[q] = o;
        const total = window.__questions.length;
        document.getElementById('answered').textContent = 'Answered: ' + Object.keys(window.__answers).length + ' / ' + total;
      }}

      function submitQuiz(total) {{
        const answers = window.__answers || {{}}, questions = window.__questions || [];
        let attempted = Object.keys(answers).length;
        let scoreable = 0, correct = 0;

        questions.forEach((q, i) => {{
          let ci = q.correctIndex;
          if (ci === undefined || ci < 0) ci = findCorrectIndex(q);
          if (ci >= 0) scoreable++;
          if (ci >= 0 && answers[i] === ci) correct++;

          document.querySelectorAll('.opt[data-q="' + i + '"]').forEach((el, j) => {{
            el.style.pointerEvents = 'none';
            if (ci >= 0) {{
              if (j === ci) el.classList.add('correct');
              else if (answers[i] === j && j !== ci) el.classList.add('wrong');
            }} else if (answers[i] === j) {{
              el.classList.add('selected');
            }}
          }});
        }});

        const rb = document.createElement('div');
        rb.className = 'result-box';

        if (scoreable === 0) {{
          rb.innerHTML = '<div class="lbl">Test Submitted</div>' +
            '<div class="score">' + attempted + ' / ' + total + '</div>' +
            '<div class="lbl">Attempted: ' + attempted + ' · Correct answers live tests me hidden hote hain</div>';
        }} else {{
          rb.innerHTML = '<div class="lbl">Your Score</div>' +
            '<div class="score">' + correct + ' / ' + total + '</div>' +
            '<div class="lbl">Attempted: ' + attempted + ' · Correct: ' + correct + ' · Wrong: ' + (attempted - correct) + '</div>';
        }}

        const quizEl = document.getElementById('quiz');
        quizEl.insertBefore(rb, quizEl.firstChild);
        rb.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
      }}

      function findCorrectIndex(q) {{
        if (!q.correctAnswer) return -1;
        const ca = String(q.correctAnswer).trim().toLowerCase();
        for (let i = 0; i < (q.options||[]).length; i++) {{
          if (String(q.options[i]).trim().toLowerCase() === ca) return i;
        }}
        return -1;
      }}

      function escapeHtml(s) {{
        if (s == null) return '';
        s = String(s);
        // Decode leftover HTML entities from server (double safety)
        const ta = document.createElement('textarea');
        ta.innerHTML = s;
        s = ta.value;
        // Then escape for safe display
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
      }}
    </script>"""
    return HTMLResponse(shell(title, body))

@app.get("/api/test-questions")
async def api_test_questions(id: str = Query(...),
                             session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return JSONResponse({"error": "not logged in", "questions": []}, status_code=401)
    try:
        result = await asyncio.wait_for(fetch_test_questions(token, id), timeout=25.0)
        return {
            "questions": result["questions"],
            "count": len(result["questions"]),
            "test_info": result.get("test_info"),
            "error": result.get("error"),
        }
    except Exception as e:
        return {"questions": [], "error": str(e)}

# ---------- Debug ----------
@app.get("/debug/probe", response_class=HTMLResponse)
async def probe(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)

    user = get_user_info(token)
    lines = [f"User: {user.get('name')} | isPaidUser: {user.get('isPaid')}", ""]

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(f"{SERIES_LIST_API}?exam=rrb-group-d&auth_code={quote(token,safe='')}", headers=tb_headers(token))
            ts = r.json().get("data", {}).get("testSeries", [])
            if ts:
                sid = ts[0]["details"]["id"]
                all_url = f"{ALL_API}?tsid={quote(sid, safe='')}&auth_code={quote(token, safe='')}&language=english"
                rr = await client.get(all_url, headers=tb_headers(token))
                data = rr.json().get("data", {})
                live = data.get("liveTests", [])
                if live:
                    test_id = live[0]["id"]
                    lines.append(f"Test: {live[0]['title']}")
                    lines.append(f"ID: {test_id}")
                    lines.append("")

                    result = await fetch_test_questions(token, test_id)
                    lines.append(f"=== PARSED RESULT ===")
                    lines.append(f"Test info: {json.dumps(result.get('test_info'), ensure_ascii=False)}")
                    lines.append(f"Questions found: {len(result['questions'])}")
                    lines.append(f"Error: {result.get('error')}")
                    lines.append("")

                    if result["questions"]:
                        lines.append("=== FIRST QUESTION (full) ===")
                        lines.append(json.dumps(result["questions"][0], ensure_ascii=False, indent=2)[:800])
    except Exception as e:
        lines.append(f"ERR: {e}")

    body = f"""<a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box">✅ FINAL — Cleaned questions + graceful scoring</div>
    <div class="debug">{chr(10).join(lines)}</div>"""
    return HTMLResponse(shell("Debug", body))
