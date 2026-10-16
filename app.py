# app.py
import os
import httpx
from fastapi import FastAPI, HTTPException
from bs4 import BeautifulSoup
from pydantic import BaseModel
from typing import List

app = FastAPI(
    title="Testbook Scraper",
    description="Scrape Testbook test series using a stored token (no OTP).",
    version="1.0.0"
)

# ---------- Config ----------
TOKEN = os.getenv("TESTBOOK_TOKEN")
if not TOKEN:
    raise RuntimeError(
        "Missing TESTBOOK_TOKEN. Set it as an env var before running."
    )

BASE_URL = "https://testbook.com"
TARGET_URL = f"{BASE_URL}/rrb-group-d/test-series/my"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; TestbookScraper/1.0)",
    "Authorization": f"Bearer {TOKEN}",
    # Add any other required headers here
}

# ---------- Models ----------
class TestInfo(BaseModel):
    title: str
    link: str
    description: str | None = None

class ScrapeResult(BaseModel):
    page_url: str
    tests: List[TestInfo]

# ---------- Helper ----------
async def fetch_page(url: str) -> str:
    """
    Fetch a page using httpx with the stored token.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=HEADERS, timeout=30.0)
        if resp.status_code != 200:
            raise HTTPException(
                status_code=resp.status_code,
                detail=f"Failed to fetch {url}"
            )
        return resp.text

def parse_tests(html: str) -> List[TestInfo]:
    """
    Very simple parser – adjust selectors as needed.
    """
    soup = BeautifulSoup(html, "html.parser")
    tests = []

    # Example: each test is inside a <div class="test-card"> (placeholder)
    cards = soup.select("div.test-card")
    if not cards:
        # Fallback – find links with specific pattern
        cards = soup.select("a[href*='/test-series/']")

    for card in cards:
        try:
            link_tag = card.find("a", href=True)
            if not link_tag:
                continue
            link = BASE_URL + link_tag["href"]
            title = link_tag.get_text(strip=True)
            desc_tag = card.find("p", class_="description")
            description = desc_tag.get_text(strip=True) if desc_tag else None
            tests.append(TestInfo(title=title, link=link, description=description))
        except Exception:
            continue
    return tests

# ---------- Routes ----------
@app.get("/", tags=["Health"])
async def health() -> dict:
    return {"status": "ok"}

@app.get("/scrape", response_model=ScrapeResult, tags=["Scraper"])
async def scrape() -> ScrapeResult:
    """
    Scrape the Testbook page and return a list of test series.
    """
    html = await fetch_page(TARGET_URL)
    tests = parse_tests(html)
    return ScrapeResult(page_url=TARGET_URL, tests=tests)
