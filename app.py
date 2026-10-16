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
from bs4 import BeautifulSoup
from fastapi import FastAPI, Form, Cookie, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Optional, List, Dict, Any
from urllib.parse import quote

app = FastAPI(title="Testbook Mirror", version="36.0.0")

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
            "isPaid": p.get("isPaidUser", False), "userId": p.get("sub") or ""}

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

# ---------- Clean text ----------
def _clean_text(s) -> str:
    if s is None: return ""
    s = str(s)
    for _ in range(4):
        new_s = html_lib.unescape(s)
        if new_s == s: break
        s = new_s
    try:
        soup = BeautifulSoup(s, "html.parser")
        s = soup.get_text()
    except Exception: pass
    s = s.replace("\u00a0", " ").replace("\t", " ")
    s = " ".join(s.split())
    return s.strip()

# ---------- ⚡ Fetch ENROLLED / RECENT series (multiple endpoints) ----------
ENROLLED_ENDPOINTS = [
    # live-panel family
    f"{API_BASE}/api/v2_1/live-panel/all",                # no tsid — may return everything
    f"{API_BASE}/api/v2_1/live-panel/my-series",
    f"{API_BASE}/api/v2_1/live-panel/enrolled",
    f"{API_BASE}/api/v2_1/live-panel/enrolled-test-series",
    f"{API_BASE}/api/v2_1/live-panel/recent-test-series",
    f"{API_BASE}/api/v2_1/live-panel/recent",
    f"{API_BASE}/api/v2_1/live-panel/home",
    f"{API_BASE}/api/v2_1/live-panel/dashboard",
    f"{API_BASE}/api/v2_1/live-panel/panel",
    f"{API_BASE}/api/v2_1/live-panel/panel-data",
    f"{API_BASE}/api/v2_1/live-panel/series",
    f"{API_BASE}/api/v2_1/live-panel/test-series",
    f"{API_BASE}/api/v2_1/live-panel/live-tests",
    f"{API_BASE}/api/v2_1/live-panel/free-quizzes",
    f"{API_BASE}/api/v2_1/live-panel/quiz",
    f"{API_BASE}/api/v2_1/live-panel/quizzes",
    # user-based
    f"{API_BASE}/api/v2_1/me/test-series",
    f"{API_BASE}/api/v2_1/me/enrolled",
    f"{API_BASE}/api/v2_1/me/dashboard",
    f"{API_BASE}/api/v2_1/users/me/test-series",
    f"{API_BASE}/api/v2_1/users/me/enrolled",
    f"{API_BASE}/api/v2_1/user/enrolled-test-series",
    f"{API_BASE}/api/v2_1/user/my-test-series",
    # v2
    f"{API_BASE}/api/v2/me/test-series",
    f"{API_BASE}/api/v2/users/me/test-series",
    f"{API_BASE}/api/v2/live-panel/all",
    # v3
    f"{API_BASE}/api/v3/me/test-series",
    f"{API_BASE}/api/v3/live-panel/all",
]

def _looks_like_series(o):
    if not isinstance(o, dict): return False
    k = set(o.keys())
    has_id = bool(k & {"id", "_id", "seriesId", "testSeriesId", "tsid", "slug"})
    has_name = bool(k & {"name", "title", "seriesName", "testSeriesName"})
    # Exclude test objects
    is_test = bool(k & {"questionCount", "totalQuestions", "testType", "duration", "posMarks"})
    return has_id and has_name and not is_test

def _looks_like_test(o):
    if not isinstance(o, dict): return False
    k = set(o.keys())
    has_id = "id" in k or "_id" in k
    has_title = "title" in k or "name" in k
    has_marker = bool(k & {"questionCount", "totalQuestions", "duration", "totalMark",
                           "totalMarks", "testType", "isFree", "posMarks"})
    return has_id and has_title and has_marker

def _walk(node, out_series, out_tests, depth=0):
    if depth > 12: return
    if isinstance(node, list):
        for x in node: _walk(x, out_series, out_tests, depth + 1)
    elif isinstance(node, dict):
        if _looks_like_series(node):
            out_series.append(node)
        elif _looks_like_test(node):
            out_tests.append(node)
        for v in node.values():
            if isinstance(v, (list, dict)):
                _walk(v, out_series, out_tests, depth + 1)

async def fetch_enrolled_and_recent(token: str) -> Dict:
    """Try many endpoints; aggregate enrolled series + live tests."""
    result = {
        "enrolled_series": [],
        "live_tests": [],
        "endpoint_hits": [],
        "errors": [],
    }
    seen_series_ids = set()
    seen_test_ids = set()

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        # Try endpoints in parallel
        async def try_endpoint(u):
            full = f"{u}{'&' if '?' in u else '?'}auth_code={quote(token, safe='')}&language=english"
            try:
                r = await client.get(full, headers=tb_headers(token))
                if r.status_code != 200:
                    return None
                j = r.json()
                if not isinstance(j, dict) or not j.get("success"):
                    return None
                return {"url": u, "data": j.get("data", {})}
            except Exception:
                return None

        tasks = [try_endpoint(u) for u in ENROLLED_ENDPOINTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception) or res is None: continue
            url = res["url"]
            data = res["data"]
            series_list = []
            tests_list = []
            _walk(data, series_list, tests_list)

            if series_list or tests_list:
                result["endpoint_hits"].append({
                    "url": url,
                    "series_count": len(series_list),
                    "tests_count": len(tests_list),
                })

            for s in series_list:
                sid = str(s.get("id") or s.get("_id") or s.get("seriesId") or s.get("tsid") or s.get("slug") or "")
                if sid and sid not in seen_series_ids:
                    seen_series_ids.add(sid)
                    result["enrolled_series"].append({
                        "id": sid,
                        "title": _clean_text(s.get("name") or s.get("title") or "Test Series"),
                        "description": _clean_text(s.get("description") or "")[:150],
                        "totalTests": s.get("totalTests") or s.get("testCount") or 0,
                        "attempted": s.get("attempted") or s.get("testsAttempted") or 0,
                    })

            for t in tests_list:
                tid = str(t.get("id") or t.get("_id") or "")
                if tid and tid not in seen_test_ids:
                    seen_test_ids.add(tid)
                    result["live_tests"].append({
                        "id": tid,
                        "title": _clean_text(t.get("title") or t.get("name") or "Test"),
                        "questionCount": t.get("questionCount") or 0,
                        "duration": t.get("duration") or 0,
                        "isFree": bool(t.get("isFree") or False),
                    })

    return result

# ---------- Fallback: series via test-series API ----------
async def fetch_series_list(token: str, exam_slug: str = "rrb-group-d") -> List[Dict]:
    url = f"{SERIES_LIST_API}?exam={quote(exam_slug, safe='')}&auth_code={quote(token, safe='')}&language=english"
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
                results.append({"id": sid, "slug": str(d.get("slug") or ""),
                                "title": _clean_text(d.get("name") or "Test Series"),
                                "description": _clean_text(str(d.get("description") or ""))[:150]})
            return results
    except Exception: return []

# ---------- Tests for a series ----------
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
        result.append({"id": tid, "title": _clean_text(t.get("title") or t.get("name") or "Test"),
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

# ---------- Questions ----------
def extract_questions_from_test_detail(data: dict) -> List[Dict]:
    questions = []
    for sec in data.get("sections", []):
        sec_title = sec.get("title", "")
        for q in sec.get("questions", []):
            if not isinstance(q, dict): continue
            qid = q.get("_id") or q.get("id") or ""

            def _parse_lang(lang_block):
                if not isinstance(lang_block, dict): return {"text": "", "options": [], "correctIndex": -1}
                txt = _clean_text(lang_block.get("value") or lang_block.get("questionText") or "")
                opts_raw = lang_block.get("options") or []
                opts = []
                ci = -1
                for i, o in enumerate(opts_raw):
                    if isinstance(o, dict):
                        opt_text = _clean_text(o.get("value") or o.get("text") or "")
                        opts.append(opt_text)
                        if o.get("isCorrect") is True or o.get("correct") is True:
                            ci = i
                    else:
                        opts.append(_clean_text(str(o)))
                return {"text": txt, "options": opts, "correctIndex": ci}

            en_data = _parse_lang(q.get("en") or {})
            hi_data = _parse_lang(q.get("hi") or {})
            primary = en_data if en_data["text"] else hi_data

            questions.append({
                "id": qid, "section": sec_title, "type": q.get("type", "mcq"),
                "text": primary["text"], "options": primary["options"],
                "text_en": en_data["text"], "options_en": en_data["options"],
                "text_hi": hi_data["text"], "options_hi": hi_data["options"],
                "posMarks": q.get("posMarks", 4), "negMarks": q.get("negMarks", 1),
                "correctIndex": primary["correctIndex"],
                "correctAnswer": q.get("correctAnswer") or q.get("correct"),
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
                "title": _clean_text(data.get("title") or "Test"),
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
.section-title{font-size:14px;font-weight:700;color:#4a5568;margin:20px 0 12px;
text-transform:uppercase;letter-spacing:.5px;display:flex;justify-content:space-between;align-items:center}
.section-title a{font-size:12px;color:#4f46e5;text-decoration:none;font-weight:600;text-transform:none;letter-spacing:normal}
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
/* Testbook-style series card with progress */
.series-card{background:#fff;border-radius:14px;padding:16px;box-shadow:0 2px 10px rgba(0,0,0,.06);
border-left:4px solid #1fbad6}
.series-card a{text-decoration:none;color:#1a202c;display:block}
.series-card h3{font-size:14px;font-weight:700;margin-bottom:8px;line-height:1.4;
display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.series-card .progress-row{display:flex;justify-content:space-between;font-size:12px;
color:#4a5568;margin-bottom:6px}
.series-card .progress-bar{height:5px;background:#e2e8f0;border-radius:3px;overflow:hidden}
.series-card .progress-bar .fill{height:100%;background:#1fbad6;border-radius:3px}
.series-card .btn-go{display:block;margin-top:12px;padding:10px;background:#1fbad6;
color:#fff;text-align:center;border-radius:8px;font-weight:700;font-size:13px}
.empty{text-align:center;padding:40px 20px;color:#a0aec0}
.empty h2{font-size:18px;margin-bottom:8px;color:#4a5568}
.btn{display:inline-block;padding:11px 20px;background:#4f46e5;color:#fff;
border:none;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;
cursor:pointer;text-align:center}
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
/* Search */
.search-box{display:flex;gap:8px;margin-bottom:18px}
.search-box input{flex:1;padding:12px 16px;border:1.5px solid #e2e8f0;border-radius:10px;
font-size:14px;outline:none}
.search-box input:focus{border-color:#4f46e5}
.search-box button{padding:12px 20px;background:#4f46e5;color:#fff;border:none;
border-radius:10px;font-weight:600;cursor:pointer}
/* Quiz */
.tb-header{background:#fff;padding:12px 16px;position:sticky;top:56px;z-index:40;
border-bottom:1px solid #e2e8f0;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.tb-header .q-num-big{font-size:24px;font-weight:800;color:#1a202c;min-width:36px}
.tb-header .q-stats{display:flex;gap:16px;font-size:12px;color:#4a5568;flex:1}
.tb-header .q-stat{display:flex;flex-direction:column;align-items:center}
.tb-header .q-stat .lbl{font-size:10px;color:#718096;text-transform:uppercase;letter-spacing:.5px}
.tb-header .q-stat .val{font-size:13px;font-weight:700}
.tb-header .marks-pos{color:#10b981}
.tb-header .marks-neg{color:#ef4444}
.tb-header .timer-box{background:#1a202c;color:#fff;padding:6px 14px;border-radius:8px;
font-family:monospace;font-size:14px;font-weight:700;letter-spacing:1px}
.tb-header .lang-select{padding:6px 12px;border:1.5px solid #e2e8f0;border-radius:8px;
font-size:13px;font-weight:600;color:#4a5568;background:#fff;cursor:pointer;outline:none}
.tb-question{padding:20px 16px;background:#fff}
.tb-question .q-text{font-size:16px;line-height:1.7;color:#1a202c;margin-bottom:20px;word-break:break-word;white-space:pre-wrap}
.tb-opt{display:flex;align-items:flex-start;gap:12px;padding:14px 16px;
background:#fff;border:1.5px solid #e2e8f0;border-radius:10px;margin-bottom:12px;
cursor:pointer;transition:all .15s;font-size:15px;color:#1a202c;line-height:1.5;user-select:none}
.tb-opt:hover{border-color:#a5b4fc;background:#f8faff}
.tb-opt.selected{border-color:#4f46e5;background:#eef2ff}
.tb-opt.correct{border-color:#10b981;background:#d1fae5}
.tb-opt.wrong{border-color:#ef4444;background:#fee2e2}
.tb-opt .radio{width:22px;height:22px;min-width:22px;border:2px solid #cbd5e0;
border-radius:50%;display:flex;align-items:center;justify-content:center;margin-top:1px}
.tb-opt.selected .radio{border-color:#4f46e5;background:#4f46e5}
.tb-opt.selected .radio::after{content:'';width:8px;height:8px;background:#fff;border-radius:50%}
.tb-opt .opt-text{flex:1;word-break:break-word}
.tb-nav{background:#fff;padding:12px 16px;display:flex;gap:10px;flex-wrap:wrap;
border-top:1px solid #e2e8f0;position:sticky;bottom:0;z-index:40;
box-shadow:0 -2px 10px rgba(0,0,0,.05)}
.tb-nav button{flex:1;min-width:100px;padding:12px;border:none;border-radius:8px;
font-size:14px;font-weight:700;cursor:pointer}
.btn-mark,.btn-clear,.btn-prev{background:#e2e8f0;color:#4a5568}
.btn-save,.btn-next{background:#1fbad6;color:#fff}
.btn-submit{background:#10b981;color:#fff}
.progress-bar{height:3px;background:#e2e8f0;position:sticky;top:104px;z-index:39}
.progress-bar .fill{height:100%;background:linear-gradient(90deg,#4f46e5,#7c3aed);transition:width .2s}
.result-box{background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff;
padding:24px;border-radius:14px;text-align:center;margin:16px}
.result-box .score{font-size:42px;font-weight:900;margin:8px 0}
.result-box .lbl{font-size:13px;opacity:.9}
.q-indicator{display:inline-flex;align-items:center;justify-content:center;
width:28px;height:28px;border-radius:6px;background:#e2e8f0;color:#4a5568;
font-size:11px;font-weight:700;margin:2px;cursor:pointer}
.q-indicator.answered{background:#4f46e5;color:#fff}
.q-indicator.current{outline:2px solid #4f46e5;outline-offset:1px}
.q-indicators{display:flex;flex-wrap:wrap;gap:4px;padding:12px 16px;background:#fff;
border-bottom:1px solid #e2e8f0}
"""

def shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Testbook Mirror</title><style>{CSS}</style></head><body>
<div class="topbar"><h1>📚 Testbook Mirror</h1>
<div class="nav"><a href="/dashboard">🏠 Home</a>
<a href="/online-test-series">📝 Series</a>
<a href="/search">🔍 Search</a>
<a href="/debug/probe">🐛 Debug</a>
<a href="/logout">Logout</a></div></div>
{body}
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
async def health(): return {"status":"ok","version":"36.0.0"}

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

# ---------- DASHBOARD (Testbook /online-test-series style) ----------
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)
    user = get_user_info(token)
    stats = await fetch_stats(token)

    # Fetch enrolled series + live tests
    agg = await fetch_enrolled_and_recent(token)

    # Fallback: if no enrolled series found, use test-series API
    if not agg["enrolled_series"]:
        fallback = []
        for slug in ("rrb-group-d", "bihar-police-si", "ssc-cgl"):
            fallback.extend(await fetch_series_list(token, slug))
        agg["enrolled_series"] = fallback[:12]

    # Stats row
    stats_html = ""
    if stats:
        stats_html = f"""<div class="stat-row">
        <div class="stat"><div class="num">{stats.get('testsCount',0)}</div><div class="lbl">Tests</div></div>
        <div class="stat"><div class="num">{stats.get('quizzesCount',0)}</div><div class="lbl">Quizzes</div></div>
        <div class="stat"><div class="num">{stats.get('videosCount',0)}</div><div class="lbl">Videos</div></div>
        </div>"""

    paid_badge = " 💎" if user.get("isPaid") else ""
    greeting = f'<div class="info-box">✅ <b>Welcome, {user["name"]}{paid_badge}!</b><br>{user["email"]}</div>'

    # Enrolled series cards (Testbook style with progress)
    series_cards = ""
    for s in agg["enrolled_series"][:12]:
        title = _clean_text(s.get("title") or "Test Series")
        desc = _clean_text(s.get("description") or "")[:100]
        total = s.get("totalTests") or 0
        att = s.get("attempted") or 0
        pct = int((att / total) * 100) if total else 0
        if not desc:
            desc = f"{total} tests" if total else "Test Series"
        series_cards += f"""
        <div class="series-card">
          <a href="/series?id={quote(s['id'], safe='')}">
            <h3>{title}</h3>
            <div class="progress-row">
              <span>{att}/{total if total else '—'}</span>
              <span>{pct}%</span>
            </div>
            <div class="progress-bar"><div class="fill" style="width:{pct}%"></div></div>
            <div class="btn-go">Go To Test Series</div>
          </a>
        </div>"""

    # Live tests cards
    live_cards = ""
    for t in agg["live_tests"][:10]:
        meta = []
        if t.get("questionCount"): meta.append(f"📝 {t['questionCount']} Qs")
        if t.get("duration"): meta.append(f"⏱ {t['duration']} min")
        if t.get("isFree"): meta.append("🆓 Free")
        live_cards += f"""
        <div class="card"><a href="/test?id={quote(t['id'], safe='')}&name={quote(t['title'], safe='')}">
          <h3>{t['title']}</h3>
          <p>{' · '.join(meta)}</p>
          <span class="badge green">Start Test →</span>
        </a></div>"""

    # Search bar
    search_html = """
    <form class="search-box" method="get" action="/search">
      <input type="text" name="q" placeholder="Search for your Exam" />
      <button type="submit">Search</button>
    </form>"""

    body = f"""<div class="container">
    {greeting}
    {stats_html}
    {search_html}

    {f'<div class="section-title">📚 Your Enrolled Test Series <a href="/online-test-series">View all →</a></div>' if series_cards else ''}
    <div class="row">{series_cards}</div>

    {f'<div class="section-title">⚡ Live Tests & Free Quizzes <a href="/online-test-series">View All →</a></div>' if live_cards else ''}
    <div class="row">{live_cards}</div>

    {f'<div class="empty"><h2>😕 Koi enrolled series nahi mili</h2><p>Token sahi hai (stats aa gaye), par series endpoints ne data nahi diya. <a href="/debug/probe">Debug</a> dekhein.</p></div>' if not series_cards and not live_cards else ''}
    </div>"""
    return HTMLResponse(shell("Dashboard", body))

# ---------- ONLINE TEST SERIES ----------
@app.get("/online-test-series", response_class=HTMLResponse)
async def online_test_series(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)

    agg = await fetch_enrolled_and_recent(token)
    all_series = agg["enrolled_series"]

    if not all_series:
        for slug in ("rrb-group-d", "bihar-police-si", "ssc-cgl", "rrb-ntpc", "ibps-po"):
            all_series.extend(await fetch_series_list(token, slug))

    cards = "".join(
        f'<div class="card"><a href="/series?id={quote(item["id"], safe="")}">'
        f'<h3>{_clean_text(item["title"])}</h3>'
        f'{f"<p>{_clean_text(item.get(chr(100)+chr(101)+chr(115)+chr(99)+chr(114)+chr(105)+chr(112)+chr(116)+chr(105)+chr(111)+chr(110), ""))[:140]}</p>" if item.get("description") else ""}'
        f'<span class="badge">Open Series →</span></a></div>'
        for item in all_series
    )

    body = f"""<div class="container">
    <a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>📝 Online Test Series ({len(all_series)})</b></div>
    <div class="row">{cards if cards else '<div class="empty"><h2>Series load nahi hui</h2></div>'}</div>
    </div>"""
    return HTMLResponse(shell("Test Series", body))

# ---------- SEARCH ----------
@app.get("/search", response_class=HTMLResponse)
async def search_page(q: str = Query(""), session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)

    results = []
    if q:
        q_lower = q.lower()
        # Search in enrolled series
        agg = await fetch_enrolled_and_recent(token)
        for s in agg["enrolled_series"]:
            if q_lower in s["title"].lower():
                results.append({"title": s["title"], "link": f'/series?id={quote(s["id"], safe="")}',
                                "type": "Enrolled Series"})
        # Search exam categories
        for ex in (("RRB Group D", "rrb-group-d"), ("RRB NTPC", "rrb-ntpc"),
                   ("SSC CGL", "ssc-cgl"), ("SSC GD", "ssc-gd"),
                   ("Bihar Police SI", "bihar-police-si"), ("UP Police", "up-police"),
                   ("IBPS PO", "ibps-po"), ("SBI PO", "sbi-po")):
            if q_lower in ex[0].lower() or q_lower in ex[1].lower():
                results.append({"title": ex[0], "link": f"/exam/{ex[1]}", "type": "Exam"})
        # Search test series in top exams
        for ex in (("RRB Group D", "rrb-group-d"), ("Bihar Police SI", "bihar-police-si")):
            series = await fetch_series_list(token, ex[1])
            for s in series:
                if q_lower in s["title"].lower():
                    results.append({"title": s["title"], "link": f'/series?id={quote(s["id"], safe="")}',
                                    "type": f"Series ({ex[0]})"})
        # Dedupe
        seen = set()
        uniq = []
        for r in results:
            if r["title"] not in seen:
                seen.add(r["title"])
                uniq.append(r)
        results = uniq

    cards = "".join(
        f'<div class="card"><a href="{r["link"]}"><h3>{r["title"]}</h3>'
        f'<span class="badge">{r["type"]}</span></a></div>'
        for r in results
    )

    body = f"""<div class="container">
    <a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>🔍 Search</b></div>
    <form class="search-box" method="get" action="/search">
      <input type="text" name="q" value="{q}" placeholder="Search for your Exam" autofocus>
      <button type="submit">Search</button>
    </form>
    {f'<div class="section-title">{len(results)} results found</div>' if q else ''}
    <div class="row">{cards}</div>
    </div>"""
    return HTMLResponse(shell("Search", body))

# ---------- EXAM PAGE ----------
@app.get("/exam/{slug}", response_class=HTMLResponse)
async def exam_page(slug: str, session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)

    series = await fetch_series_list(token, slug)
    title = slug.replace("-", " ").title()

    cards = "".join(
        f'<div class="card"><a href="/series?id={quote(item["id"], safe="")}">'
        f'<h3>{_clean_text(item["title"])}</h3>'
        f'<span class="badge">Open Series →</span></a></div>'
        for item in series
    )

    body = f"""<div class="container">
    <a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>📖 {title}</b><br>{len(series)} test series</div>
    <div class="row">{cards if cards else '<div class="empty"><h2>Is exam ke liye series nahi mili</h2></div>'}</div>
    </div>"""
    return HTMLResponse(shell(title, body))

# ---------- SERIES PAGE ----------
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
                    title = _clean_text(j.get("data", {}).get("details", {}).get("name") or title)
    except Exception: pass

    body = f"""<div class="container"><a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>📚 {title}</b></div>
    <div id="loading" class="loading-box">
      <div class="spinner"></div>
      <p>Tests load ho rahe hain...</p>
    </div>
    <div id="results"></div></div>
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

# ---------- TEST PAGE (quiz with Hindi) ----------
@app.get("/test", response_class=HTMLResponse)
async def test_page(id: str = Query(...), name: str = Query(""),
                    session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)
    title = name or "Test"
    body = f"""<div id="loading" class="loading-box">
      <div class="spinner"></div>
      <p>Questions load ho rahe hain...</p>
    </div>
    <div id="quiz"></div>
    <script>
      const TEST_ID = {json.dumps(id)};
      const TEST_NAME = {json.dumps(title)};
      fetch('/api/test-questions?id=' + encodeURIComponent(TEST_ID))
        .then(r => r.json())
        .then(data => {{
          document.getElementById('loading').style.display = 'none';
          const box = document.getElementById('quiz');
          if (!data.questions || data.questions.length === 0) {{
            box.innerHTML = '<div class="empty"><h2>😕 Questions load nahi ho paye</h2>' +
              '<p>' + (data.error || '') + '</p>' +
              '<a href="/debug/probe" class="btn" style="margin-top:12px;">🔍 Debug</a></div>';
            return;
          }}
          renderQuiz(data.questions, data.test_info || {{}});
        }});

      function renderQuiz(questions, info) {{
        window.__answers = {{}};
        window.__questions = questions;
        window.__current = 0;
        window.__marked = {{}};
        window.__lang = 'en';
        window.__timeLeft = (info.duration || 30) * 60;
        window.__timerInterval = null;

        let html = '<div class="container" style="padding:0;max-width:100%">';
        html += '<div class="tb-header">' +
          '<span class="q-num-big" id="qNum">1.</span>' +
          '<div class="q-stats">' +
          '<div class="q-stat"><span class="lbl">Marks</span>' +
          '<span class="val" id="qMarks"><span class="marks-pos">+' + (questions[0].posMarks || 4) + '</span> / ' +
          '<span class="marks-neg">-' + (questions[0].negMarks || 1) + '</span></span></div>' +
          '<div class="q-stat"><span class="lbl">Time</span><span class="val" id="qTime">00:00</span></div>' +
          '</div>' +
          '<div class="timer-box" id="mainTimer">--:--</div>' +
          '<select class="lang-select" id="langSelect" onchange="switchLang(this.value)">' +
          '<option value="en">English</option><option value="hi">हिंदी</option></select>' +
          '</div>';
        html += '<div class="progress-bar"><div class="fill" id="progressFill" style="width:0%"></div></div>';
        html += '<div class="q-indicators" id="indicators"></div>';
        html += '<div class="tb-question" id="questionArea"></div>';
        html += '<div class="tb-nav">' +
          '<button class="btn-mark" onclick="markForReview()">Mark for Review</button>' +
          '<button class="btn-clear" onclick="clearResponse()">Clear</button>' +
          '<button class="btn-prev" onclick="prevQuestion()">← Prev</button>' +
          '<button class="btn-save" onclick="saveAndNext()">Save & Next →</button>' +
          '<button class="btn-submit" onclick="submitQuiz()">Submit</button>' +
          '</div>';
        html += '</div>';
        document.getElementById('quiz').innerHTML = html;
        renderCurrentQuestion();
        startTimer();
      }}

      function renderCurrentQuestion() {{
        const q = window.__questions[window.__current];
        const lang = window.__lang;
        const qText = (lang === 'hi' && q.text_hi) ? q.text_hi : (q.text_en || q.text);
        const qOpts = (lang === 'hi' && q.options_hi && q.options_hi.length) ? q.options_hi : (q.options_en || q.options);

        document.getElementById('qNum').textContent = (window.__current + 1) + '.';
        document.getElementById('qMarks').innerHTML =
          '<span class="marks-pos">+' + (q.posMarks || 4) + '</span> / ' +
          '<span class="marks-neg">-' + (q.negMarks || 1) + '</span>';

        let html = '<div class="q-text">' + escapeHtml(qText) + '</div>';
        qOpts.forEach((opt, j) => {{
          const sel = window.__answers[window.__current] === j ? 'selected' : '';
          html += '<div class="tb-opt ' + sel + '" data-opt="' + j + '" onclick="pickOption(' + j + ')">' +
            '<div class="radio"></div>' +
            '<div class="opt-text">' + escapeHtml(opt) + '</div></div>';
        }});
        document.getElementById('questionArea').innerHTML = html;
        renderIndicators();
        updateProgress();
      }}

      function renderIndicators() {{
        let html = '';
        for (let i = 0; i < window.__questions.length; i++) {{
          const cls = (i === window.__current ? 'current ' : '') +
                      (window.__answers[i] !== undefined ? 'answered' : '');
          html += '<div class="q-indicator ' + cls + '" onclick="jumpTo(' + i + ')">' + (i+1) + '</div>';
        }}
        document.getElementById('indicators').innerHTML = html;
      }}

      function pickOption(j) {{
        window.__answers[window.__current] = j;
        document.querySelectorAll('.tb-opt').forEach(el => el.classList.remove('selected'));
        document.querySelector('.tb-opt[data-opt="' + j + '"]').classList.add('selected');
        renderIndicators(); updateProgress();
      }}

      function clearResponse() {{ delete window.__answers[window.__current]; renderCurrentQuestion(); }}
      function markForReview() {{ window.__marked[window.__current] = !window.__marked[window.__current]; }}
      function saveAndNext() {{ if (window.__current < window.__questions.length - 1) {{ window.__current++; renderCurrentQuestion(); window.scrollTo({{top:0,behavior:'smooth'}}); }} }}
      function prevQuestion() {{ if (window.__current > 0) {{ window.__current--; renderCurrentQuestion(); window.scrollTo({{top:0,behavior:'smooth'}}); }} }}
      function jumpTo(i) {{ window.__current = i; renderCurrentQuestion(); window.scrollTo({{top:0,behavior:'smooth'}}); }}
      function switchLang(l) {{ window.__lang = l; renderCurrentQuestion(); }}

      function updateProgress() {{
        const total = window.__questions.length;
        const ans = Object.keys(window.__answers).length;
        document.getElementById('progressFill').style.width = (ans / total) * 100 + '%';
      }}

      function startTimer() {{
        if (window.__timerInterval) clearInterval(window.__timerInterval);
        updateTimerDisplay();
        window.__timerInterval = setInterval(() => {{
          if (window.__timeLeft <= 0) {{ clearInterval(window.__timerInterval); submitQuiz(); return; }}
          window.__timeLeft--; updateTimerDisplay();
        }}, 1000);
      }}

      function updateTimerDisplay() {{
        const t = window.__timeLeft;
        const h = Math.floor(t / 3600), m = Math.floor((t % 3600) / 60), s = t % 60;
        const pad = (n) => String(n).padStart(2, '0');
        document.getElementById('mainTimer').textContent = (h > 0 ? pad(h) + ':' : '') + pad(m) + ':' + pad(s);
      }}

      function submitQuiz() {{
        if (!confirm('Submit karein?')) return;
        if (window.__timerInterval) clearInterval(window.__timerInterval);
        const answers = window.__answers || {{}}, questions = window.__questions || [];
        let attempted = Object.keys(answers).length;
        let correct = 0, wrong = 0, scoreable = 0;
        questions.forEach((q, i) => {{
          let ci = q.correctIndex;
          if (ci === undefined || ci < 0) ci = -1;
          if (ci >= 0) {{ scoreable++; if (answers[i] === ci) correct++; else if (answers[i] !== undefined) wrong++; }}
        }});
        const rb = document.createElement('div');
        rb.className = 'result-box';
        if (scoreable === 0) {{
          rb.innerHTML = '<div class="lbl">Test Submitted ✅</div>' +
            '<div class="score">' + attempted + ' / ' + questions.length + '</div>' +
            '<div class="lbl">Attempted · Live test me correct answers hidden hote hain</div>' +
            '<button class="btn" style="background:#fff;color:#4f46e5;margin-top:16px;" onclick="window.location.reload()">🔄 Retake</button>';
        }} else {{
          rb.innerHTML = '<div class="lbl">Your Score</div>' +
            '<div class="score">' + correct + ' / ' + questions.length + '</div>' +
            '<div class="lbl">Attempted: ' + attempted + ' · Correct: ' + correct + ' · Wrong: ' + wrong + '</div>' +
            '<button class="btn" style="background:#fff;color:#4f46e5;margin-top:16px;" onclick="window.location.reload()">🔄 Retake</button>';
        }}
        document.getElementById('quiz').innerHTML = '';
        document.getElementById('quiz').appendChild(rb);
        window.scrollTo({{ top: 0, behavior: 'smooth' }});
      }}

      function escapeHtml(s) {{
        if (s == null) return '';
        return String(s).replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
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
        return {"questions": result["questions"], "count": len(result["questions"]),
                "test_info": result.get("test_info"), "error": result.get("error")}
    except Exception as e:
        return {"questions": [], "error": str(e)}

# ---------- Debug: which endpoint returns enrolled series ----------
@app.get("/debug/probe", response_class=HTMLResponse)
async def probe(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)
    user = get_user_info(token)

    lines = [f"User: {user.get('name')} | isPaidUser: {user.get('isPaid')}", ""]
    lines.append("=== PROBING ENROLLED SERIES ENDPOINTS ===")
    lines.append(f"Total endpoints: {len(ENROLLED_ENDPOINTS)}\n")

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        async def try_endpoint(u):
            full = f"{u}{'&' if '?' in u else '?'}auth_code={quote(token, safe='')}&language=english"
            try:
                r = await client.get(full, headers=tb_headers(token))
                status = r.status_code
                body_preview = ""
                series_count = 0
                tests_count = 0
                if status == 200:
                    try:
                        j = r.json()
                        data = j.get("data", {})
                        series_list, tests_list = [], []
                        _walk(data, series_list, tests_list)
                        series_count = len(series_list)
                        tests_count = len(tests_list)
                        body_preview = json.dumps(data, ensure_ascii=False)[:150]
                    except Exception:
                        body_preview = r.text[:100]
                return {"url": u, "status": status, "series": series_count,
                        "tests": tests_count, "preview": body_preview}
            except Exception as e:
                return {"url": u, "status": -1, "series": 0, "tests": 0, "preview": str(e)[:100]}

        tasks = [try_endpoint(u) for u in ENROLLED_ENDPOINTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    winners = []
    for res in results:
        if isinstance(res, Exception): continue
        st = res["status"]
        if st == 200 and (res["series"] > 0 or res["tests"] > 0):
            winners.append(res)
            lines.append(f"✅ [{st}] series={res['series']} tests={res['tests']}  {res['url']}")
            if res["preview"]:
                lines.append(f"      {res['preview']}")
        elif st == 200:
            lines.append(f"⚠️  [200] empty  {res['url']}")
        elif st in (400, 401, 403, 405):
            lines.append(f"❌ [{st}]  {res['url']}")

    lines.append("")
    lines.append(f"=== WINNERS: {len(winners)} ===")
    for w in winners:
        lines.append(f"  → {w['url']} (series={w['series']}, tests={w['tests']})")

    body = f"""<div class="container"><a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box">🔍 Enrolled series endpoints ka result</div>
    <div class="debug">{chr(10).join(lines)}</div></div>"""
    return HTMLResponse(shell("Debug", body))
