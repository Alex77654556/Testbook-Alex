# app.py
import os
import re
import json
import time
import hmac
import base64
import hashlib
import httpx
from fastapi import FastAPI, Form, Cookie, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response as FastResponse
from bs4 import BeautifulSoup
from typing import Optional
from urllib.parse import quote

app = FastAPI(title="Testbook Proxy", version="7.0.0")

BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

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
    payload = decode_jwt_payload(token)
    if payload is None:
        return False, "Token JWT format me nahi hai"
    exp = payload.get("exp")
    if exp and isinstance(exp, (int, float)) and exp < time.time():
        return False, "Token expire ho gaya hai"
    if not any(k in payload for k in ("sub", "email", "name", "phone")):
        return False, "Token me user info nahi mili"
    return True, "ok"

# ---------- Interceptor JS ----------
INTERCEPTOR_JS = r"""
(function(){
  var P = '/tb';
  function fix(u){
    try{
      if(typeof u !== 'string') return u;
      if(u.indexOf('https://testbook.com') === 0) return P + u.slice(19);
      if(u.indexOf('http://testbook.com') === 0) return P + u.slice(18);
      if(u.indexOf('//testbook.com') === 0) return P + u.slice(15);
      if(u.indexOf('https://www.testbook.com') === 0) return P + u.slice(23);
      if(u.indexOf('//www.testbook.com') === 0) return P + u.slice(19);
      if(u.indexOf('https://api.testbook.com') === 0) return '/tb-api' + u.slice(23);
      if(u.indexOf('//api.testbook.com') === 0) return '/tb-api' + u.slice(19);
      if(u.charAt(0) === '/' && u.charAt(1) !== '/' && u.indexOf(P+'/') !== 0 && u !== P) return P + u;
      return u;
    }catch(e){ return u; }
  }
  window.__tbFix = fix;

  try {
    var _l = window.location;
    delete window.location;
    window.location = new Proxy(_l, {
      get: function(t,p){
        if(p==='href') return _l.href;
        if(p==='assign') return function(u){ return _l.assign(fix(u)); };
        if(p==='replace') return function(u){ return _l.replace(fix(u)); };
        var v=_l[p]; return typeof v==='function'?v.bind(_l):v;
      },
      set: function(t,p,v){ if(p==='href'){ _l.href=fix(v); return true; } _l[p]=v; return true; }
    });
  } catch(e){}

  try {
    var _ps=history.pushState,_rs=history.replaceState;
    history.pushState=function(s,t,u){return _ps.call(this,s,t,u?fix(u):u);};
    history.replaceState=function(s,t,u){return _rs.call(this,s,t,u?fix(u):u);};
  } catch(e){}

  try { var _o=window.open; window.open=function(u,n,f){return _o.call(this,u?fix(u):u,n,f);}; } catch(e){}

  try {
    var _f=window.fetch;
    if(_f){
      window.fetch=function(input,init){
        try {
          if(typeof input==='string') input=fix(input);
          else if(input&&input.url){ var nu=fix(input.url); if(nu!==input.url){ try{input=new Request(nu,input);}catch(e){} } }
        } catch(e){}
        init=init||{};
        init.credentials='same-origin';
        return _f.call(this,input,init);
      };
    }
  } catch(e){}

  try {
    var _x=XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open=function(m,u){
      var rest=Array.prototype.slice.call(arguments,2);
      return _x.apply(this,[m,fix(u)].concat(rest));
    };
  } catch(e){}

  document.addEventListener('click',function(e){
    try{
      var el=e.target; while(el&&el.tagName!=='A') el=el.parentElement;
      if(!el) return;
      var href=el.getAttribute('href');
      if(!href) return;
      var fixed=fix(href);
      if(fixed!==href){ e.preventDefault(); e.stopPropagation(); window.location.href=fixed; }
    }catch(err){}
  },true);
})();
"""

def rewrite_html(html_text: str, token: str) -> str:
    soup = BeautifulSoup(html_text, "html.parser")

    for meta in soup.find_all("meta"):
        he = (meta.get("http-equiv") or "").lower()
        if he in ("content-security-policy","content-security-policy-report-only","refresh"):
            meta.decompose()

    base = soup.find("base")
    if base:
        base["href"] = "/tb/"
    else:
        nb = soup.new_tag("base", href="/tb/")
        if soup.head:
            soup.head.insert(0, nb)

    pairs = [("a","href"),("link","href"),("script","src"),("img","src"),
             ("source","src"),("iframe","src"),("form","action"),
             ("video","src"),("video","poster"),("audio","src"),
             ("use","href"),("use","xlink:href"),("object","data"),
             ("embed","src"),("track","src"),("input","src"),("area","href")]

    for tag,attr in pairs:
        for el in soup.find_all(tag):
            v = el.get(attr)
            if not v or not isinstance(v,str): continue
            if v.startswith(("#","javascript:","mailto:","tel:","data:","blob:")): continue
            if v.startswith("https://api.testbook.com"):
                el[attr] = "/tb-api" + v[len("https://api.testbook.com"):]
            elif v.startswith("//api.testbook.com"):
                el[attr] = "/tb-api" + v[len("//api.testbook.com"):]
            elif v.startswith("https://testbook.com"):
                el[attr] = "/tb" + v[len("https://testbook.com"):]
            elif v.startswith("http://testbook.com"):
                el[attr] = "/tb" + v[len("http://testbook.com"):]
            elif v.startswith("//testbook.com"):
                el[attr] = "/tb" + v[len("//testbook.com"):]
            elif v.startswith("https://www.testbook.com"):
                el[attr] = "/tb" + v[len("https://www.testbook.com"):]
            elif v.startswith("//www.testbook.com"):
                el[attr] = "/tb" + v[len("//www.testbook.com"):]
            elif v.startswith("/") and not v.startswith("//"):
                el[attr] = "/tb" + v

    sc = soup.new_tag("script")
    sc.string = INTERCEPTOR_JS
    if soup.head:
        soup.head.insert(0, sc)

    cs = soup.new_tag("script")
    cs.string = f"document.cookie='tb_token={token}; path=/; max-age=604800; SameSite=Lax';"
    if soup.head:
        soup.head.insert(0, cs)

    return str(soup)

def _copy_cookies(resp, upstream):
    for sc in upstream.headers.get_list("set-cookie"):
        sc = re.sub(r';\s*[Dd]omain=[^;]+', '', sc)
        sc = re.sub(r';\s*[Ss]ecure', '', sc)
        sc = re.sub(r';\s*[Ss]ame[Ss]ite=None', '; SameSite=Lax', sc)
        try:
            resp.headers.append("set-cookie", sc)
        except Exception:
            pass
    return resp

async def proxy_page(path: str, query: str, token: str, cookies: dict):
    target = f"{BASE_URL}/{path.lstrip('/')}"
    if query:
        target += "?" + query

    headers = {
        "User-Agent": UA,
        "Authorization": f"Bearer {token}",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Referer": BASE_URL + "/",
    }
    cookie_parts = [f"tb_token={token}"]
    for k, v in cookies.items():
        if k in ("tb_session","tb_token"): continue
        cookie_parts.append(f"{k}={v}")
    headers["Cookie"] = "; ".join(cookie_parts)

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as client:
            r = await client.get(target, headers=headers)
    except Exception as e:
        return HTMLResponse(f"<h1>Upstream error</h1><pre>{e}</pre>", status_code=502)

    if r.status_code in (301,302,303,307,308):
        loc = r.headers.get("location","/")
        if loc.startswith(BASE_URL):
            loc = "/tb" + loc[len(BASE_URL):]
        elif loc.startswith("/") and not loc.startswith("/tb"):
            loc = "/tb" + loc
        resp = RedirectResponse(loc, status_code=r.status_code)
        return _copy_cookies(resp, r)

    ctype = r.headers.get("content-type","").lower()
    if "text/html" in ctype:
        text = rewrite_html(r.text, token)
        resp = HTMLResponse(text, status_code=r.status_code)
        for h in ("x-frame-options","content-security-policy","content-security-policy-report-only"):
            if h in resp.headers:
                del resp.headers[h]
        return _copy_cookies(resp, r)

    resp = FastResponse(content=r.content, status_code=r.status_code,
                        media_type=r.headers.get("content-type","application/octet-stream"))
    return _copy_cookies(resp, r)

async def proxy_api(path: str, query: str, token: str, method: str, body: bytes, cookies: dict, headers_in: dict):
    target = f"{API_BASE}/{path.lstrip('/')}"
    if query:
        target += "?" + query

    headers = {
        "User-Agent": UA,
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Referer": BASE_URL + "/",
        "Origin": BASE_URL,
    }
    for h in ("content-type","x-requested-with","x-xsrf-token","x-csrf-token"):
        if headers_in.get(h):
            headers[h.title()] = headers_in[h]

    cookie_parts = [f"tb_token={token}"]
    for k, v in cookies.items():
        if k in ("tb_session","tb_token"): continue
        cookie_parts.append(f"{k}={v}")
    headers["Cookie"] = "; ".join(cookie_parts)

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as client:
            r = await client.request(method, target, headers=headers, content=body if body else None)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)

    resp = FastResponse(content=r.content, status_code=r.status_code,
                        media_type=r.headers.get("content-type","application/json"))
    return _copy_cookies(resp, r)

# ---------- Login page ----------
LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login · Testbook Proxy</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;
display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:18px;box-shadow:0 20px 60px rgba(0,0,0,.3);
padding:40px;width:100%;max-width:500px}
h1{color:#1a202c;font-size:22px;text-align:center;margin-bottom:6px}
p.sub{color:#718096;font-size:13px;text-align:center;margin-bottom:26px;line-height:1.6}
label{display:block;font-size:13px;color:#4a5568;font-weight:600;margin-bottom:8px}
textarea{width:100%;padding:13px 14px;border:1.5px solid #e2e8f0;border-radius:10px;
font-size:13px;font-family:ui-monospace,Menlo,Consolas,monospace;resize:vertical}
textarea:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.15)}
button{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);
color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;margin-top:20px}
button:hover{opacity:.92}
.hint{margin-top:22px;padding:14px;background:#f7fafc;border-radius:10px;font-size:12px;color:#4a5568;line-height:1.75}
.hint b{color:#2d3748}
.hint code{background:#edf2f7;padding:1px 6px;border-radius:4px;font-size:11px}
.error{background:#fff5f5;color:#c53030;padding:12px;border-radius:8px;font-size:13px;margin-bottom:16px;border:1px solid #fed7d7;text-align:center}
</style></head><body>
<div class="card">
<h1>🔐 Testbook Token Login</h1>
<p class="sub">Token daaliye — poori Testbook website aapke domain se live chalegi.</p>
__ERROR__
<form method="post" action="/login">
<label>Access Token</label>
<textarea name="token" rows="6" placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." required autofocus></textarea>
<button type="submit">Login karein →</button>
</form>
<div class="hint">
<b>🔑 Token kahan milega?</b><br>
1. <b>testbook.com</b> par login karein<br>
2. <b>F12</b> → <b>Network</b> → <b>Fetch/XHR</b><br>
3. Koi bhi <code>api.testbook.com</code> request<br>
4. URL me <code>auth_code=eyJ...</code> ya Headers me <code>Authorization: Bearer eyJ...</code><br>
5. Sirf <code>eyJ...</code> wala part copy karein
</div>
</div></body></html>"""

# ---------- Routes ----------
@app.get("/health")
async def health():
    return {"status": "ok", "version": "7.0.0"}

@app.get("/", response_class=HTMLResponse)
async def root(error: Optional[str] = None,
               session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    if get_token(session_cookie):
        return RedirectResponse("/tb/", status_code=302)
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
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", f'<div class="error">❌ {msg}</div>'), status_code=401)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(
                f"{API_BASE}/api/v2_1/live-panel/count?auth_code={quote(token,safe='')}&language=english",
                headers={"User-Agent": UA, "Authorization": f"Bearer {token}"}
            )
            if r.status_code != 200 or not r.json().get("success"):
                return HTMLResponse(LOGIN_HTML.replace("__ERROR__", '<div class="error">❌ Token invalid ya expire.</div>'), status_code=401)
    except Exception as e:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", f'<div class="error">Connection error: {e}</div>'), status_code=502)

    resp = RedirectResponse("/tb/", status_code=303)
    resp.set_cookie("tb_session", sign_token(token), httponly=True, samesite="lax", max_age=7*24*3600, secure=False)
    return resp

@app.get("/logout")
async def logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("tb_session")
    return resp

@app.api_route("/tb", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"])
@app.api_route("/tb/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"])
async def tb_proxy(request: Request, path: str = "",
                   session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)
    return await proxy_page(path, request.url.query, token, dict(request.cookies))

@app.api_route("/tb-api/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"])
async def tb_api_proxy(request: Request, path: str = "",
                       session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return JSONResponse({"error": "not logged in"}, status_code=401)
    body = await request.body()
    return await proxy_api(path, request.url.query, token, request.method, body,
                           dict(request.cookies), dict(request.headers))
