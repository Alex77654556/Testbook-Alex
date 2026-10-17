# app.py
import os
import json
import time
import hmac
import base64
import hashlib
import asyncio
import re
import secrets
from datetime import datetime, timezone
import httpx
import html as html_lib
from bs4 import BeautifulSoup
from fastapi import FastAPI, Form, Cookie, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Optional, List, Dict, Any
from urllib.parse import quote

app = FastAPI(title="Testbook Mirror", version="38.0.0",
              docs_url=None, redoc_url=None, openapi_url=None)

BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
# Use a strong persistent SESSION_SECRET in cloud deployments. If omitted, use an
# ephemeral local-development secret rather than a known hard-coded key.
SESSION_SECRET = os.getenv("SESSION_SECRET") or secrets.token_urlsafe(48)
COOKIE_SECURE = os.getenv(
    "COOKIE_SECURE", "true" if os.getenv("VERCEL") else "false"
).strip().lower() in {"1", "true", "yes", "on"}
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

COUNT_API = f"{API_BASE}/api/v2_1/live-panel/count"
ALL_API = f"{API_BASE}/api/v2_1/live-panel/all"
SERIES_LIST_API = f"{API_BASE}/api/v2_1/test-series"


# ---------- HTML escape ----------
def esc(s) -> str:
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&#39;"))


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


def _jwt_exp_timestamp(exp) -> Optional[float]:
    """Parse standard numeric JWT exp values and ISO-8601 exp values."""
    if isinstance(exp, bool) or exp is None:
        return None
    if isinstance(exp, (int, float)):
        return float(exp)
    if isinstance(exp, str):
        value = exp.strip()
        if not value:
            return None
        try:
            return float(value)
        except ValueError:
            pass
        try:
            # Testbook tokens may encode exp as an ISO-8601 string rather than
            # the numeric Unix timestamp required by the JWT standard.
            normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (ValueError, OverflowError):
            return None
    return None


def get_token(session_cookie: Optional[str]) -> Optional[str]:
    if not session_cookie:
        return None
    token = unsign_token(session_cookie)
    if not token:
        return None
    valid, _ = validate_jwt(token)
    return token if valid else None


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
    if exp is not None:
        exp_ts = _jwt_exp_timestamp(exp)
        if exp_ts is None:
            return False, "Token expiry format samajh nahi aaya"
        if exp_ts <= time.time():
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
                if j.get("success"):
                    return j.get("data", {})
    except Exception:
        pass
    return None


# ---------- Clean text ----------
def _clean_text(s) -> str:
    if s is None:
        return ""
    s = str(s)
    for _ in range(4):
        new_s = html_lib.unescape(s)
        if new_s == s:
            break
        s = new_s
    try:
        soup = BeautifulSoup(s, "html.parser")
        s = soup.get_text()
    except Exception:
        pass
    s = s.replace("\u00a0", " ").replace("\t", " ")
    return " ".join(s.split()).strip()


# ---------- 🆕 Exam slug registry ----------
COMMON_EXAM_SLUGS = [
    "ssc-mts", "ssc-cgl", "ssc-chsl", "ssc-gd", "ssc-cpo", "ssc-stenographer",
    "rrb-group-d", "rrb-ntpc", "rrb-alp", "rrb-je",
    "bihar-police-si", "bihar-police-constable", "bssc-inter-level", "bssc-cgl",
    "up-police", "upsssc-pet", "ibps-po", "ibps-clerk", "sbi-po", "sbi-clerk",
    "rrb-group-d", "uppsc", "bpsc", "railway-group-d",
]


def title_to_slug(title: str) -> str:
    """Convert exam title to slug: 'SSC MTS' -> 'ssc-mts'"""
    if not title:
        return ""
    s = title.lower().strip()
    s = s.replace("&", "and").replace(".", "").replace(",", "")
    s = "-".join(s.split())
    import re
    s = re.sub(r"[^a-z0-9\-]", "", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s


async def discover_exam_slugs(token: str) -> List[str]:
    """Auto-discover exam slugs from user's JWT + live-panel."""
    slugs = set()
    user = get_user_info(token)
    payload = decode_jwt_payload(token) or {}

    # From JWT targets
    for t in (payload.get("targets") or []):
        if isinstance(t, dict):
            t_slug = t.get("slug") or title_to_slug(t.get("title", ""))
            if t_slug:
                slugs.add(t_slug)

    # From live-panel specificExams
    try:
        url = f"{ALL_API}?auth_code={quote(token, safe='')}&language=english"
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.get(url, headers=tb_headers(token))
            if r.status_code == 200:
                j = r.json()
                data = j.get("data", {})
                for lt in (data.get("liveTests") or []):
                    for ex in (lt.get("specificExams") or []):
                        s = title_to_slug(ex.get("title", ""))
                        if s and len(s) > 2:
                            slugs.add(s)
    except Exception:
        pass

    # Add common slugs as fallback
    for s in COMMON_EXAM_SLUGS:
        slugs.add(s)

    return list(slugs)


# ---------- 🆕 Fetch series for an exam ----------
def _extract_series_from_obj(obj):
    if not isinstance(obj, dict):
        return None
    details = obj.get("details") or obj.get("testSeries") or obj.get("series") or {}
    if not isinstance(details, dict):
        details = {}
    prog = obj.get("progress") or {}
    if not isinstance(prog, dict):
        prog = {}

    sid = (obj.get("id") or obj.get("_id") or obj.get("seriesId")
           or obj.get("testSeriesId") or obj.get("tsid") or obj.get("slug")
           or details.get("id") or details.get("_id")
           or details.get("slug") or details.get("tsid"))
    name = (obj.get("name") or obj.get("title") or obj.get("seriesName")
            or obj.get("testSeriesName")
            or details.get("name") or details.get("title") or details.get("seriesName"))
    if not sid or not name:
        return None

    keys = set(obj.keys()) | set(details.keys())
    if keys & {"questionCount", "totalQuestions", "testType", "posMarks"} and "details" not in obj:
        return None

    attempted = (prog.get("attempted") or prog.get("testsAttempted")
                 or obj.get("attempted") or obj.get("testsAttempted") or 0)
    total = (prog.get("total") or prog.get("totalTests")
             or obj.get("totalTests") or obj.get("testCount") or 0)

    has_access = bool(obj.get("hasAccess") or details.get("hasAccess")
                     or obj.get("isPurchased") or details.get("isPurchased"))
    purchase_info = obj.get("purchaseInfo") or details.get("purchaseInfo") or []
    is_free = any(isinstance(p, dict) and p.get("type") == "Free" for p in purchase_info)

    return {
        "id": str(sid),
        "title": _clean_text(name),
        "description": _clean_text(str(obj.get("description") or details.get("description") or ""))[:150],
        "totalTests": int(total) if isinstance(total, (int, float)) else 0,
        "attempted": int(attempted) if isinstance(attempted, (int, float)) else 0,
        "hasAccess": has_access,
        "isFree": is_free,
    }


def _extract_test_from_obj(obj):
    if not isinstance(obj, dict):
        return None
    details = obj.get("details") or {}
    if not isinstance(details, dict):
        details = {}
    tid = obj.get("id") or obj.get("_id") or details.get("id") or details.get("_id")
    title = obj.get("title") or obj.get("name") or details.get("title") or details.get("name")
    if not tid or not title:
        return None
    keys = set(obj.keys()) | set(details.keys())
    if not (keys & {"questionCount", "totalQuestions", "duration", "totalMark",
                    "totalMarks", "testType", "isFree", "posMarks"}):
        return None
    return {
        "id": str(tid),
        "title": _clean_text(title),
        "questionCount": obj.get("questionCount") or obj.get("totalQuestions") or 0,
        "duration": obj.get("duration") or 0,
        "isFree": bool(obj.get("isFree") or False),
    }


def _walk(node, out_series, out_tests, depth=0):
    if depth > 15:
        return
    if isinstance(node, list):
        for x in node:
            _walk(x, out_series, out_tests, depth + 1)
    elif isinstance(node, dict):
        s = _extract_series_from_obj(node)
        if s:
            out_series.append(s)
        t = _extract_test_from_obj(node)
        if t:
            out_tests.append(t)
        for v in node.values():
            if isinstance(v, (list, dict)):
                _walk(v, out_series, out_tests, depth + 1)


async def fetch_series_for_exam(token: str, exam_slug: str) -> Dict:
    """Fetch ALL test series for a given exam slug. Tries multiple patterns."""
    user = get_user_info(token)
    uid = user.get("userId", "")

    patterns = [
        f"{API_BASE}/api/v2_1/test-series?exam={quote(exam_slug, safe='')}",
        f"{API_BASE}/api/v2_1/test-series?exam={quote(exam_slug, safe='')}&my=true",
        f"{API_BASE}/api/v2_1/test-series/my?exam={quote(exam_slug, safe='')}",
        f"{API_BASE}/api/v2_1/test-series?exam={quote(exam_slug, safe='')}&filter=my",
        f"{API_BASE}/api/v2_1/test-series?exam={quote(exam_slug, safe='')}&enrolled=true",
        f"{API_BASE}/api/v2_1/test-series?exam={quote(exam_slug, safe='')}&purchased=true",
    ]
    if uid:
        patterns += [
            f"{API_BASE}/api/v2_1/users/{uid}/test-series?exam={quote(exam_slug, safe='')}",
            f"{API_BASE}/api/v2_1/exams/{quote(exam_slug, safe='')}/test-series/my",
        ]

    result = {"series": [], "tests": [], "hits": [], "errors": []}

    async with httpx.AsyncClient(follow_redirects=True, timeout=12.0) as client:
        async def try_one(u):
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

        results = await asyncio.gather(*[try_one(u) for u in patterns], return_exceptions=True)

        seen_ids = set()
        for res in results:
            if isinstance(res, Exception) or res is None:
                continue
            series_list, tests_list = [], []
            _walk(res["data"], series_list, tests_list)
            if series_list or tests_list:
                result["hits"].append({"url": res["url"], "series": len(series_list), "tests": len(tests_list)})
            for s in series_list:
                if s["id"] not in seen_ids:
                    seen_ids.add(s["id"])
                    result["series"].append(s)
            for t in tests_list:
                result["tests"].append(t)

    return result


async def fetch_enrolled_and_recent(token: str) -> Dict:
    """Try many endpoints for enrolled series + live tests."""
    result = {"enrolled_series": [], "live_tests": [], "endpoint_hits": [], "errors": []}
    seen_series_ids = set()
    seen_test_ids = set()

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
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

        endpoints = [
            f"{API_BASE}/api/v2_1/live-panel/all",
            f"{API_BASE}/api/v2_1/live-panel/count",
        ]
        tasks = [try_endpoint(u) for u in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception) or res is None:
                continue
            series_list, tests_list = [], []
            _walk(res["data"], series_list, tests_list)
            if series_list or tests_list:
                result["endpoint_hits"].append({
                    "url": res["url"], "series_count": len(series_list), "tests_count": len(tests_list),
                })
            for s in series_list:
                if s["id"] not in seen_series_ids:
                    seen_series_ids.add(s["id"])
                    result["enrolled_series"].append(s)
            for t in tests_list:
                if t["id"] not in seen_test_ids:
                    seen_test_ids.add(t["id"])
                    result["live_tests"].append(t)

    return result


# ---------- Tests for a series ----------
def is_series_or_section(o):
    if not isinstance(o, dict):
        return False
    k = set(o.keys())
    return ("branches" in k and "examStages" in k) or ("subsections" in k and "superSectionId" in k)


def find_all_tests(node, out, depth=0):
    if depth > 15:
        return
    if isinstance(node, list):
        for x in node:
            find_all_tests(x, out, depth + 1)
    elif isinstance(node, dict):
        if not is_series_or_section(node):
            keys = set(node.keys())
            if ("id" in keys or "_id" in keys) and ("title" in keys or "name" in keys):
                if keys & {"questionCount", "totalQuestions", "duration", "totalMark", "totalMarks", "testType"}:
                    out.append(node)
        for v in node.values():
            if isinstance(v, (list, dict)):
                find_all_tests(v, out, depth + 1)


def normalize_tests(raw):
    seen, result = set(), []
    for t in raw:
        tid = str(t.get("id") or t.get("_id") or "")
        if not tid or tid in seen:
            continue
        seen.add(tid)
        result.append({
            "id": tid,
            "title": _clean_text(t.get("title") or t.get("name") or "Test"),
            "questionCount": t.get("questionCount") or 0,
            "duration": t.get("duration") or 0,
            "totalMarks": t.get("totalMarks") or t.get("totalMark") or 0,
            "isFree": bool(t.get("isFree") or False),
        })
    return result


async def fetch_all_tests_for_series(token: str, series_id: str) -> List[Dict]:
    url = f"{ALL_API}?tsid={quote(series_id, safe='')}&auth_code={quote(token, safe='')}&language=english"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            if r.status_code != 200:
                return []
            j = r.json()
            if not j.get("success"):
                return []
            raw = []
            find_all_tests(j.get("data", {}), raw)
            return normalize_tests(raw)
    except Exception:
        return []


# ---------- Questions ----------
def extract_questions_from_test_detail(data: dict) -> List[Dict]:
    questions = []
    for sec in data.get("sections", []):
        sec_title = sec.get("title", "")
        for q in sec.get("questions", []):
            if not isinstance(q, dict):
                continue
            qid = q.get("_id") or q.get("id") or ""

            def _parse_lang(lang_block):
                if not isinstance(lang_block, dict):
                    return {"text": "", "options": [], "correctIndex": -1}
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
    """Try multiple endpoint patterns for test questions."""
    s = quote(test_id, safe="")
    patterns = [
        f"{API_BASE}/api/v2_1/tests/{s}",
        f"{API_BASE}/api/v2_1/tests/{s}?attemptNo=1",
        f"{API_BASE}/api/v2_1/tests/{s}/detail",
        f"{API_BASE}/api/v2_1/tests/{s}/questions",
        f"{API_BASE}/api/v2_1/test/{s}",
        f"{API_BASE}/api/v2_1/tests/{s}/start",
    ]

    result = {"questions": [], "test_info": None, "error": None, "endpoint_used": None}

    async with httpx.AsyncClient(timeout=15.0) as client:
        for u in patterns:
            full = f"{u}{'&' if '?' in u else '?'}auth_code={quote(token, safe='')}&language=english"
            try:
                r = await client.get(full, headers=tb_headers(token))
                if r.status_code != 200:
                    continue
                j = r.json()
                if not j.get("success"):
                    continue
                data = j.get("data", {})
                qs = extract_questions_from_test_detail(data)
                if not qs:
                    # Try other shapes
                    for key in ("questions", "testQuestions"):
                        if isinstance(data.get(key), list):
                            qs = extract_questions_from_test_detail({"sections": [{"questions": data[key]}]})
                            break
                if qs:
                    dur = data.get("duration") or 0
                    if dur > 1000:
                        dur = dur // 60
                    result["test_info"] = {
                        "title": _clean_text(data.get("title") or "Test"),
                        "duration": dur,
                        "totalQuestions": len(qs),
                    }
                    result["questions"] = qs
                    result["endpoint_used"] = u
                    return result
            except Exception:
                continue

    result["error"] = "All test-question endpoints failed"
    return result


# ---------- Error handlers ----------
@app.exception_handler(StarletteHTTPException)
async def http_exc(request: Request, exc: StarletteHTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def all_exc(request: Request, exc: Exception):
    import traceback
    print("ERROR:", traceback.format_exc())
    return HTMLResponse("<h1>Error</h1><p>Kuch galat ho gaya. /raw dump bhejo.</p>", status_code=500)


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
.badge.red{background:#fee2e2;color:#dc2626}
.row{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
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
.search-box{display:flex;gap:8px;margin-bottom:18px}
.search-box input{flex:1;padding:12px 16px;border:1.5px solid #e2e8f0;border-radius:10px;
font-size:14px;outline:none}
.search-box input:focus{border-color:#4f46e5}
.search-box button{padding:12px 20px;background:#4f46e5;color:#fff;border:none;
border-radius:10px;font-weight:600;cursor:pointer}
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
.slug-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.slug-chip{background:#fff;border:1.5px solid #e2e8f0;border-radius:20px;
padding:6px 14px;font-size:12px;font-weight:600;color:#4f46e5;text-decoration:none;
cursor:pointer}
.slug-chip:hover{background:#eef2ff;border-color:#4f46e5}
"""


def shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} · Testbook Mirror</title><style>{CSS}</style></head><body>
<div class="topbar"><h1>📚 Testbook Mirror</h1>
<div class="nav"><a href="/dashboard">🏠 Home</a>
<a href="/online-test-series">📝 All Series</a>
<a href="/search">🔍 Search</a>
<a href="/raw">🐛 Raw</a>
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
async def health():
    return {"status": "ok", "version": "38.0.0"}


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
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", '<div class="error">Token khali hai.</div>'), status_code=400)
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if "auth_code=" in token:
        token = token.split("auth_code=")[1].split("&")[0]
    ok, msg = validate_jwt(token)
    if not ok:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", f'<div class="error">❌ {esc(msg)}</div>'), status_code=401)
    stats = await fetch_stats(token)
    if stats is None:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", '<div class="error">❌ Token invalid ya expire.</div>'), status_code=401)
    resp = RedirectResponse("/dashboard", status_code=303)
    exp_ts = _jwt_exp_timestamp((decode_jwt_payload(token) or {}).get("exp"))
    cookie_lifetime = 7 * 24 * 3600
    if exp_ts is not None:
        cookie_lifetime = min(cookie_lifetime, max(1, int(exp_ts - time.time())))
    resp.set_cookie(
        "tb_session", sign_token(token), httponly=True, samesite="lax",
        max_age=cookie_lifetime, secure=COOKIE_SECURE,
    )
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
    agg = await fetch_enrolled_and_recent(token)

    # Stats
    stats_html = ""
    if stats:
        stats_html = f"""<div class="stat-row">
        <div class="stat"><div class="num">{stats.get('testsCount',0)}</div><div class="lbl">Tests</div></div>
        <div class="stat"><div class="num">{stats.get('quizzesCount',0)}</div><div class="lbl">Quizzes</div></div>
        <div class="stat"><div class="num">{stats.get('videosCount',0)}</div><div class="lbl">Videos</div></div>
        </div>"""

    paid_badge = " 💎" if user.get("isPaid") else ""
    greeting = f'<div class="info-box">✅ <b>Welcome, {esc(user["name"])}{paid_badge}!</b><br>{esc(user["email"])}</div>'

    # Live tests
    live_cards = ""
    for t in agg["live_tests"][:12]:
        meta = []
        if t.get("questionCount"):
            meta.append(f"📝 {t['questionCount']} Qs")
        if t.get("duration"):
            meta.append(f"⏱ {t['duration']} min")
        if t.get("isFree"):
            meta.append("🆓 Free")
        live_cards += f"""
        <div class="card"><a href="/test?id={quote(t['id'], safe='')}&name={quote(t['title'], safe='')}">
          <h3>{esc(t['title'])}</h3>
          <p>{' · '.join(meta)}</p>
          <span class="badge green">Start Test →</span>
        </a></div>"""

    # Manual exam slug entry
    slug_form = """
    <div class="section-title">🎯 Exam Slug Se Test Series Kholo</div>
    <div class="info-box">
      <b>Kaise pata karein apna exam slug?</b><br>
      Testbook URL dekho: <code>testbook.com/<b>ssc-mts</b>/test-series/my</code><br>
      Yahan <b>ssc-mts</b> hi aapka exam slug hai. Neeche daal ke Enter karo.
    </div>
    <form class="search-box" method="get" action="/exam">
      <input type="text" name="slug" placeholder="e.g. ssc-mts, ssc-cgl, rrb-group-d" required>
      <button type="submit">Open Exam →</button>
    </form>
    <div class="slug-list">
      <span style="font-size:12px;color:#718096;margin-right:8px">Quick:</span>
    """

    for s in ["ssc-mts", "ssc-cgl", "ssc-chsl", "ssc-gd", "rrb-group-d", "rrb-ntpc", "bihar-police-si", "ibps-po"]:
        slug_form += f'<a class="slug-chip" href="/exam?slug={quote(s)}">{s}</a>'
    slug_form += "</div>"

    body = f"""<div class="container">
    {greeting}
    {stats_html}

    {slug_form}

    {f'<div class="section-title">⚡ Live Tests & Free Quizzes</div>' if live_cards else ''}
    <div class="row">{live_cards}</div>

    {f'<div class="empty"><h2>😕 Koi enrolled series nahi mili</h2><p>Upar exam slug daal ke dekho — e.g. <b>ssc-mts</b>. Ya <a href="/raw">Raw Debug</a> kholo.</p></div>' if not live_cards else ''}
    </div>"""
    return HTMLResponse(shell("Dashboard", body))


@app.get("/online-test-series", response_class=HTMLResponse)
async def online_test_series(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    # Try common exams
    all_series = []
    seen = set()
    for slug in ["ssc-mts", "ssc-cgl", "ssc-chsl", "ssc-gd", "rrb-group-d", "rrb-ntpc"]:
        r = await fetch_series_for_exam(token, slug)
        for s in r["series"]:
            if s["id"] not in seen:
                seen.add(s["id"])
                s["_exam"] = slug
                all_series.append(s)

    cards = ""
    for item in all_series[:60]:
        access_badge = ""
        if item.get("hasAccess"):
            access_badge = '<span class="badge green">✓ Access</span>'
        elif item.get("isFree"):
            access_badge = '<span class="badge">Free</span>'
        else:
            access_badge = '<span class="badge orange">Paid</span>'
        cards += (
            f'<div class="card"><a href="/series?id={quote(item["id"], safe="")}">'
            f'<h3>{esc(_clean_text(item["title"]))}</h3>'
            f'{f"<p>{esc(_clean_text(item.get(chr(100)+chr(101)+chr(115)+chr(99)+chr(114)+chr(105)+chr(112)+chr(116)+chr(105)+chr(111)+chr(110), ""))[:140])}</p>" if item.get("description") else ""}'
            f'{access_badge}'
            f'<span class="badge">Open →</span></a></div>'
        )

    body = f"""<div class="container">
    <a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>📝 Online Test Series ({len(all_series)})</b><br>Common exams se auto-fetched.</div>
    <div class="row">{cards if cards else '<div class="empty"><h2>Series load nahi hui</h2><p>Exam slug se try karo.</p></div>'}</div>
    </div>"""
    return HTMLResponse(shell("Test Series", body))


@app.get("/exam", response_class=HTMLResponse)
async def exam_page(slug: str = Query(...), session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    r = await fetch_series_for_exam(token, slug)
    series = r["series"]
    tests = r["tests"]

    title = slug.replace("-", " ").title()

    series_cards = ""
    for item in series:
        access_badge = ""
        if item.get("hasAccess"):
            access_badge = '<span class="badge green">✓ Access</span>'
        elif item.get("isFree"):
            access_badge = '<span class="badge">Free</span>'
        else:
            access_badge = '<span class="badge orange">Paid</span>'

        prog_html = ""
        if item.get("totalTests"):
            pct = int((item["attempted"] / item["totalTests"]) * 100) if item["totalTests"] else 0
            prog_html = f"""
            <div class="progress-row"><span>{item['attempted']}/{item['totalTests']}</span><span>{pct}%</span></div>
            <div class="progress-bar"><div class="fill" style="width:{pct}%"></div></div>"""

        series_cards += f"""
        <div class="series-card">
          <a href="/series?id={quote(item['id'], safe='')}">
            <h3>{esc(item['title'])}</h3>
            {prog_html}
            {access_badge}
            <div class="btn-go">Go To Test Series</div>
          </a>
        </div>"""

    # Standalone tests
    test_cards = ""
    for t in tests[:20]:
        meta = []
        if t.get("questionCount"):
            meta.append(f"📝 {t['questionCount']} Qs")
        if t.get("duration"):
            meta.append(f"⏱ {t['duration']} min")
        test_cards += f"""
        <div class="card"><a href="/test?id={quote(t['id'], safe='')}&name={quote(t['title'], safe='')}">
          <h3>{esc(t['title'])}</h3><p>{' · '.join(meta)}</p>
          <span class="badge green">Start Test →</span></a></div>"""

    debug_info = ""
    if r["hits"]:
        debug_info = f'<div class="info-box" style="font-size:11px">✅ Endpoints hit: {", ".join(h["url"].replace(API_BASE, "") for h in r["hits"])}</div>'

    body = f"""<div class="container">
    <a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>📖 {esc(title)}</b> — exam slug: <code>{esc(slug)}</code><br>{len(series)} series · {len(tests)} standalone tests</div>
    {debug_info}

    {f'<div class="section-title">📚 Test Series ({len(series)})</div><div class="row">{series_cards}</div>' if series_cards else ''}
    {f'<div class="section-title">⚡ Standalone Tests ({len(tests)})</div><div class="row">{test_cards}</div>' if test_cards else ''}
    {f'<div class="empty"><h2>Is exam me kuch nahi mila</h2><p>Slug galat ho sakta hai. <a href="/raw?custom=/api/v2_1/test-series?exam={quote(slug)}">Raw se check karo →</a></p></div>' if not series_cards and not test_cards else ''}
    </div>"""
    return HTMLResponse(shell(title, body))


@app.get("/search", response_class=HTMLResponse)
async def search_page(q: str = Query(""), session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    results = []
    if q:
        q_lower = q.lower()
        slug = title_to_slug(q)
        # Try as exam slug
        for ex_slug in [q_lower, slug]:
            r = await fetch_series_for_exam(token, ex_slug)
            for s in r["series"]:
                if q_lower in s["title"].lower() or ex_slug in s.get("_exam", ""):
                    results.append({"title": s["title"], "link": f'/series?id={quote(s["id"], safe="")}',
                                    "type": f"Series ({ex_slug})"})
        # Dedupe
        seen = set()
        uniq = []
        for r in results:
            if r["title"] not in seen:
                seen.add(r["title"])
                uniq.append(r)
        results = uniq

    cards = "".join(
        f'<div class="card"><a href="{esc(r["link"])}"><h3>{esc(r["title"])}</h3>'
        f'<span class="badge">{esc(r["type"])}</span></a></div>'
        for r in results
    )

    body = f"""<div class="container">
    <a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>🔍 Search</b> — exam slug ya series title</div>
    <form class="search-box" method="get" action="/search">
      <input type="text" name="q" value="{esc(q)}" placeholder="ssc-mts, SSC CGL, RRB..." autofocus>
      <button type="submit">Search</button>
    </form>
    {f'<div class="section-title">{len(results)} results</div>' if q else ''}
    <div class="row">{cards}</div>
    </div>"""
    return HTMLResponse(shell("Search", body))


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
                    title = _clean_text(j.get("data", {}).get("details", {}).get("name") or title)
    except Exception:
        pass

    body = f"""<div class="container"><a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>📚 {esc(title)}</b></div>
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
            box.innerHTML = '<div class="empty"><h2>😕 Tests nahi mile</h2><p><a href="/raw">Raw debug →</a></p></div>';
            return;
          }}
          let html = '<div class="section-title">📝 Tests (' + data.tests.length + ')</div><div class="row">';
          for (const t of data.tests) {{
            const meta = [];
            if (t.questionCount) meta.push('📝 ' + t.questionCount + ' Qs');
            if (t.duration) meta.push('⏱ ' + t.duration + ' min');
            if (t.totalMarks) meta.push('🎯 ' + t.totalMarks + ' marks');
            html += '<div class="card"><a href="/test?id=' + encodeURIComponent(t.id) + '&name=' + encodeURIComponent(t.title) + '">' +
              '<h3>' + esc(t.title) + '</h3><p>' + meta.join(' · ') + '</p>' +
              '<span class="badge green">Start Test →</span></a></div>';
          }}
          html += '</div>';
          box.innerHTML = html;
        }});
      function esc(s) {{
        return String(s||'').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
      }}
    </script>"""
    return HTMLResponse(shell(title, body))


@app.get("/api/series-tests")
async def api_series_tests(id: str = Query(...),
                           session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return JSONResponse({"error": "not logged in", "tests": []}, status_code=401)
    try:
        tests = await asyncio.wait_for(fetch_all_tests_for_series(token, id), timeout=30.0)
        return {"tests": tests, "count": len(tests)}
    except Exception as e:
        return {"tests": [], "error": str(e)}


@app.get("/test", response_class=HTMLResponse)
async def test_page(id: str = Query(...), name: str = Query(""),
                    session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)
    title = name or "Test"
    body = f"""<div id="loading" class="loading-box">
      <div class="spinner"></div>
      <p>Questions load ho rahe hain...</p>
    </div>
    <div id="quiz"></div>
    <script>
      const TEST_ID = {json.dumps(id)};
      fetch('/api/test-questions?id=' + encodeURIComponent(TEST_ID))
        .then(r => r.json())
        .then(data => {{
          document.getElementById('loading').style.display = 'none';
          const box = document.getElementById('quiz');
          if (!data.questions || data.questions.length === 0) {{
            box.innerHTML = '<div class="empty"><h2>😕 Questions load nahi ho paye</h2>' +
              '<p>' + esc(data.error || '') + '</p>' +
              '<a href="/raw" class="btn" style="margin-top:12px;">🐛 Raw Debug</a></div>';
            return;
          }}
          renderQuiz(data.questions, data.test_info || {{}});
        }});

      function renderQuiz(questions, info) {{
        window.__answers = {{}};
        window.__questions = questions;
        window.__current = 0;
        window.__lang = 'en';
        window.__timeLeft = (info.duration || 30) * 60;
        window.__timerInterval = null;

        let html = '<div class="container" style="padding:0;max-width:100%">';
        html += '<div class="tb-header">' +
          '<span class="q-num-big" id="qNum">1.</span>' +
          '<div class="q-stats">' +
          '<div class="q-stat"><span class="lbl">Marks</span>' +
          '<span class="val" id="qMarks"></span></div>' +
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
          '<button class="btn-mark" onclick="markForReview()">Mark</button>' +
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
        const pm = q.posMarks || 4;
        const nm = q.negMarks || 1;
        document.getElementById('qMarks').innerHTML =
          '<span class="marks-pos">+' + pm + '</span> / <span class="marks-neg">-' + nm + '</span>';

        let html = '<div class="q-text">' + esc(qText) + '</div>';
        qOpts.forEach((opt, j) => {{
          const sel = window.__answers[window.__current] === j ? 'selected' : '';
          html += '<div class="tb-opt ' + sel + '" data-opt="' + j + '" onclick="pickOption(' + j + ')">' +
            '<div class="radio"></div>' +
            '<div class="opt-text">' + esc(opt) + '</div></div>';
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
      function markForReview() {{ alert('Marked'); }}
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

      function esc(s) {{
        if (s == null) return '';
        return String(s).replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
      }}
    </script>"""
    return HTMLResponse(shell(title, body))


@app.get("/api/test-questions")
async def api_test_questions(id: str = Query(...),
                             session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return JSONResponse({"error": "not logged in", "questions": []}, status_code=401)
    try:
        result = await asyncio.wait_for(fetch_test_questions(token, id), timeout=25.0)
        return {"questions": result["questions"], "count": len(result["questions"]),
                "test_info": result.get("test_info"), "error": result.get("error"),
                "endpoint_used": result.get("endpoint_used")}
    except Exception as e:
        return {"questions": [], "error": str(e)}


# ============================================================
# 🐛 RAW DATA VIEWER
# ============================================================

def _validate_raw_url(url: str) -> Optional[str]:
    url = (url or "").strip()
    if not url:
        return None
    if url.startswith("/api/") or url.startswith("/v2") or url.startswith("/v3"):
        return API_BASE + url
    if url.startswith("https://api.testbook.com/") or url.startswith("http://api.testbook.com/"):
        return url
    return None


def _pretty(obj, max_len=100000) -> str:
    try:
        s = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    except Exception:
        s = str(obj)
    if len(s) > max_len:
        s = s[:max_len] + f"\n\n... [truncated — total {len(s)} chars]"
    return s


async def _diagnose(token: str, target: str, timeout: float = 15.0) -> dict:
    url = _validate_raw_url(target)
    if not url:
        return {"error": "URL not allowed — sirf /api/... ya api.testbook.com", "input": target}
    sep = "&" if "?" in url else "?"
    full = url if "auth_code=" in url else f"{url}{sep}auth_code={quote(token, safe='')}&language=english"

    # Never echo the credential-bearing URL into the browser or logs.
    safe_display_url = re.sub(r"(?i)([?&]auth_code=)[^&]*", r"\1[REDACTED]", full)
    safe_input = re.sub(r"(?i)([?&]auth_code=)[^&]*", r"\1[REDACTED]", target)
    info = {
        "input": safe_input, "url": safe_display_url, "status": None, "elapsed_ms": None,
        "response_size": 0, "content_type": None,
        "body_json": None, "body_text": None, "error": None,
        "headers": {}, "series": [], "tests": [],
    }
    t0 = time.time()
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as c:
            r = await c.get(full, headers=tb_headers(token))
            info["elapsed_ms"] = round((time.time() - t0) * 1000)
            info["status"] = r.status_code
            info["content_type"] = r.headers.get("content-type", "")
            info["response_size"] = len(r.content)
            info["headers"] = {k: v for k, v in r.headers.items()
                               if k.lower() in ("content-type", "content-length", "server",
                                                "x-ratelimit-remaining", "x-request-id", "date")}
            try:
                info["body_json"] = r.json()
                _walk(info["body_json"], info["series"], info["tests"])
            except Exception:
                info["body_text"] = r.text[:30000]
    except Exception as e:
        info["elapsed_ms"] = round((time.time() - t0) * 1000)
        info["error"] = f"{type(e).__name__}: {e}"
    return info


@app.get("/api/raw/probe-all")
async def api_raw_probe_all(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return JSONResponse({"error": "not logged in", "results": []}, status_code=401)

    user = get_user_info(token)
    slugs = await discover_exam_slugs(token)

    # Test a few key endpoints per slug
    endpoints = []
    for slug in slugs[:6]:
        endpoints.append(f"/api/v2_1/test-series?exam={slug}")
        endpoints.append(f"/api/v2_1/test-series?exam={slug}&my=true")
    endpoints += [
        "/api/v2_1/live-panel/all",
        "/api/v2_1/live-panel/count",
        "/api/v2_1/test-series",
        f"/api/v2_1/users/{user['userId']}/test-series",
    ]

    async def one(ep):
        d = await _diagnose(token, ep, timeout=10.0)
        return {
            "endpoint": ep, "status": d.get("status"),
            "response_size": d.get("response_size", 0),
            "elapsed_ms": d.get("elapsed_ms"),
            "detected": {"series": d.get("series", []), "tests": d.get("tests", [])},
            "error": d.get("error"),
        }

    results = await asyncio.gather(*[one(ep) for ep in endpoints], return_exceptions=True)
    clean = [r for r in results if isinstance(r, dict)]
    return {"results": clean, "count": len(clean), "exam_slugs_tried": slugs[:6]}


@app.get("/api/raw/one")
async def api_raw_one(ep: str = Query(...),
                      session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return JSONResponse({"error": "not logged in"}, status_code=401)
    return await _diagnose(token, ep)


@app.get("/raw/full")
async def raw_full(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    user = get_user_info(token)
    slugs = await discover_exam_slugs(token)

    async def one(ep):
        d = await _diagnose(token, ep, timeout=12.0)
        d.pop("body_text", None)
        return d

    # Key endpoints
    endpoints = [
        "/api/v2_1/live-panel/all",
        "/api/v2_1/live-panel/count",
        f"/api/v2_1/users/{user['userId']}/test-series",
        "/api/v2_1/test-series",
    ]
    for slug in slugs[:5]:
        endpoints.append(f"/api/v2_1/test-series?exam={slug}")

    results = await asyncio.gather(*[one(ep) for ep in endpoints], return_exceptions=True)
    payload = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "user": user,
        "exam_slugs_tried": slugs,
        "endpoints_tried": len(endpoints),
        "results": [r for r in results if isinstance(r, dict)],
    }
    return JSONResponse(payload, headers={
        "Content-Disposition": 'attachment; filename="testbook_raw_dump.json"'
    })


@app.get("/raw", response_class=HTMLResponse)
async def raw_page(ep: Optional[str] = Query(None),
                   custom: Optional[str] = Query(None),
                   session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    user = get_user_info(token)

    target = ep or custom
    if target:
        d = await _diagnose(token, target)
        st = d.get("status")
        if st == 200:
            status_badge = '<span style="color:#10b981">200 OK</span>'
        elif st:
            status_badge = f'<span style="color:#f59e0b">{st}</span>'
        else:
            status_badge = '<span style="color:#ef4444">ERROR</span>'

        raw_body = _pretty(d.get("body_json")) if d.get("body_json") is not None else (d.get("body_text") or d.get("error") or "(empty)")
        json_escaped = esc(raw_body)

        series_summary = ""
        if d.get("series"):
            series_summary = f'<div class="section-title">✅ Detected as SERIES ({len(d["series"])})</div>'
            for s in d["series"][:20]:
                series_summary += f'<div class="card"><h3>{esc(s["title"])}</h3><p>id={esc(s["id"])} · access={s.get("hasAccess")}</p><span class="badge">Series</span></div>'
        if d.get("tests"):
            series_summary += f'<div class="section-title">✅ Detected as TESTS ({len(d["tests"])})</div>'
            for t in d["tests"][:20]:
                series_summary += f'<div class="card"><h3>{esc(t["title"])}</h3><p>id={esc(t["id"])}</p><span class="badge green">Test</span></div>'

        headers_html = "".join(
            f"<tr><td style='padding:4px 10px;font-family:monospace;color:#718096'>{esc(k)}</td>"
            f"<td style='padding:4px 10px;font-family:monospace'>{esc(v)}</td></tr>"
            for k, v in d.get("headers", {}).items()
        )

        body = f"""<div class="container">
        <a href="/raw" class="back-btn">← All Endpoints</a>
        <div class="info-box"><b>🔍 Raw Response</b><br>
          <code style="font-size:11px;word-break:break-all">{esc(d['url'])}</code></div>
        <div class="stat-row">
          <div class="stat"><div class="num">{status_badge}</div><div class="lbl">Status</div></div>
          <div class="stat"><div class="num">{d.get('response_size',0)}</div><div class="lbl">Bytes</div></div>
          <div class="stat"><div class="num">{d.get('elapsed_ms') or '—'}ms</div><div class="lbl">Latency</div></div>
          <div class="stat"><div class="num">{len(d.get('series',[]))}</div><div class="lbl">Series</div></div>
          <div class="stat"><div class="num">{len(d.get('tests',[]))}</div><div class="lbl">Tests</div></div>
        </div>
        {series_summary}
        <div class="section-title">📄 Full Raw JSON
          <a href="#" onclick="copyJson();return false;">📋 Copy</a></div>
        <textarea id="jsonBox" style="width:100%;min-height:400px;padding:14px;border-radius:10px;border:1.5px solid #e2e8f0;font-family:monospace;font-size:11px;background:#1a202c;color:#a0aec0;resize:vertical">{json_escaped}</textarea>
        <div class="section-title">📨 Response Headers</div>
        <table style="width:100%;background:#fff;border-radius:10px;font-size:12px;border-collapse:collapse">{headers_html or '<tr><td style="padding:10px;color:#a0aec0">No headers</td></tr>'}</table>
        <div style="margin-top:20px;display:flex;gap:8px;flex-wrap:wrap">
          <a href="/raw?ep={quote(d['url'], safe='')}" class="btn">🔄 Refresh</a>
          <a href="/raw/full" class="btn" style="background:#10b981">📥 Download ALL</a>
        </div>
        <script>
          function copyJson() {{
            const t = document.getElementById('jsonBox');
            t.select(); t.setSelectionRange(0, 99999);
            navigator.clipboard.writeText(t.value);
            alert('JSON copied');
          }}
        </script></div>"""
        return HTMLResponse(shell(f"Raw · {target[:40]}", body))

    body = f"""<div class="container">
    <a href="/dashboard" class="back-btn">← Dashboard</a>
    <div class="info-box">
      <b>🐛 Raw Data Viewer</b><br>
      User: {esc(user['name'])} · isPaid: {user['isPaid']} · userId: {esc(user['userId'])}<br>
      Yahan dikhega kaunsa endpoint actually data de raha hai.
    </div>

    <div class="section-title">🌐 Custom Endpoint</div>
    <form class="search-box" method="get" action="/raw">
      <input type="text" name="custom" placeholder="/api/v2_1/test-series?exam=ssc-mts" required>
      <button type="submit">Fetch →</button>
    </form>

    <div class="section-title">🎯 Exam Slug Test</div>
    <form class="search-box" method="get" action="/raw">
      <input type="text" name="ep" value="/api/v2_1/test-series?exam=ssc-mts" placeholder="/api/v2_1/test-series?exam=ssc-mts">
      <button type="submit">Test Slug →</button>
    </form>

    <div class="section-title">📡 Live Probe</div>
    <p style="color:#718096;font-size:12px;margin-bottom:12px">✅ = data mila, ⚠️ = empty, ❌ = error.</p>
    <div id="endpointList">
      <div class="loading-box"><div class="spinner"></div><p>Probing endpoints...</p></div>
    </div>

    <div style="margin-top:20px;display:flex;gap:8px;flex-wrap:wrap">
      <a href="/raw/full" class="btn" style="background:#10b981">📥 Download ALL raw data (JSON)</a>
    </div>
    </div>

    <script>
      fetch('/api/raw/probe-all').then(r => r.json()).then(data => {{
        const list = document.getElementById('endpointList');
        if (!data.results || !data.results.length) {{
          list.innerHTML = '<div class="empty">No response</div>';
          return;
        }}
        let html = '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;background:#fff;border-radius:12px;font-size:12px;box-shadow:0 2px 8px rgba(0,0,0,.06)">';
        html += '<tr style="background:#eef2ff;text-align:left">'
          + '<th style="padding:10px">Status</th><th style="padding:10px">Endpoint</th>'
          + '<th style="padding:10px">Size</th><th style="padding:10px">Series</th>'
          + '<th style="padding:10px">Tests</th><th style="padding:10px">Action</th></tr>';
        for (const r of data.results) {{
          const st = r.status;
          const statusColor = st === 200 ? '#10b981' : (st >= 400 ? '#ef4444' : '#f59e0b');
          const statusText = st === null ? '❌ ERR' : st;
          const shortUrl = r.endpoint.replace('https://api.testbook.com', '');
          const sc = (r.detected && r.detected.series) ? r.detected.series.length : 0;
          const tc = (r.detected && r.detected.tests) ? r.detected.tests.length : 0;
          const sz = r.response_size ? Math.round(r.response_size/1024) + 'KB' : '—';
          const bg = (sc > 0 || tc > 0) ? 'background:#f0fdf4' : (st === 200 ? '' : 'background:#fef2f2');
          html += '<tr style="border-bottom:1px solid #e2e8f0;' + bg + '">';
          html += '<td style="padding:8px;color:' + statusColor + ';font-weight:700">' + statusText + '</td>';
          html += '<td style="padding:8px;font-family:monospace;word-break:break-all;font-size:11px">' + esc(shortUrl) + '</td>';
          html += '<td style="padding:8px">' + sz + '</td>';
          html += '<td style="padding:8px">' + (sc > 0 ? '✅ ' + sc : '—') + '</td>';
          html += '<td style="padding:8px">' + (tc > 0 ? '✅ ' + tc : '—') + '</td>';
          html += '<td style="padding:8px"><a href="/raw?ep=' + encodeURIComponent(r.endpoint) + '" style="color:#4f46e5;font-weight:700">View Raw →</a></td>';
          html += '</tr>';
        }}
        html += '</table></div>';
        list.innerHTML = html;
      }}).catch(e => {{
        document.getElementById('endpointList').innerHTML = '<div class="empty">Error: ' + e + '</div>';
      }});
      function esc(s) {{
        return String(s||'').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
      }}
    </script>"""
    return HTMLResponse(shell("Raw Debug", body))


@app.get("/debug/probe", response_class=HTMLResponse)
async def probe(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)
    return RedirectResponse("/raw", status_code=302)


# ---------- Run ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
