# Testbook Mirror — authorized-account client

This FastAPI app uses a Testbook JWT supplied by the signed-in account holder to display content the upstream Testbook API authorizes for that account. It does **not** unlock subscriptions, paid tests, hidden questions, or other access-controlled material. If Testbook denies an item, the app cannot legitimately make it available.

## Run locally

Requires Python 3.10+.

```bash
cd Testbook-Alex
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

# Set a private, stable cookie-signing secret (keep it out of Git/chat):
export SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

On Windows PowerShell, set the secret with:

```powershell
$env:SESSION_SECRET = python -c "import secrets; print(secrets.token_urlsafe(48))"
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`. `/health` is a simple health check. Log in only through the app's form, over HTTPS when deployed. Never paste a JWT into source code, an issue, or a public chat; revoke a token immediately if it has been exposed.

## Deployment notes

The included `vercel.json` is the existing Vercel entrypoint. Configure these environment variables in the hosting provider:

- `SESSION_SECRET`: a long random value, stable across instances/restarts. Generate one with `python -c 'import secrets; print(secrets.token_urlsafe(48))'`.
- `COOKIE_SECURE=true` when serving over HTTPS (defaults to `true` on Vercel and `false` for local HTTP).

Deploy only to an account you control. This project is an unofficial client; upstream API behavior and availability can change. A valid login does not imply access to every Testbook product.

## Token handling / troubleshooting

- JWT expiry claims may be numeric Unix timestamps or ISO-8601 strings; both are parsed. The browser session cookie will not outlive the JWT.
- The app does not store a token in this repository. The token is held in an HTTP-only signed session cookie and sent to Testbook's configured API.
- If an entitled item is missing, check the account's Testbook access first, then use the app's diagnostics to inspect the upstream response. Share only a screenshot or status/error with credentials and personal data redacted.

## Tests

```bash
python -m unittest discover -s tests -v
```
