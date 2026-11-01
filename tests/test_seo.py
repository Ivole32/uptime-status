import dataclasses
import xml.etree.ElementTree as ET

import pytest

from app.checker import ProbeResult
from app.config import _url, get_settings
from app.main import app
from app.scheduler import record_result

MONITOR = {"name": "Website", "url": "example.com", "interval_seconds": 60, "timeout_seconds": 10}
NS = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}


@pytest.fixture
def site_url():
    settings = dataclasses.replace(get_settings(), public_url="https://status.example.com")
    app.dependency_overrides[get_settings] = lambda: settings
    yield settings.public_url
    app.dependency_overrides.pop(get_settings, None)


def _urls(res) -> dict[str, str | None]:
    assert res.status_code == 200 and res.headers["content-type"].startswith("application/xml")
    root = ET.fromstring(res.content)
    return {
        url.findtext("s:loc", namespaces=NS): url.findtext("s:lastmod", namespaces=NS)
        for url in root.findall("s:url", NS)
    }


def test_robots_without_site_url(client):
    res = client.get("/robots.txt")
    assert res.status_code == 200 and res.headers["content-type"].startswith("text/plain")
    assert "Disallow: /admin\n" in res.text and "Disallow: /api/admin/\n" in res.text
    assert "Sitemap" not in res.text
    assert client.get("/sitemap.xml").status_code == 404


def test_sitemap_csp_allows_only_the_browser_xml_viewer(client, site_url):
    # Browsers style their XML tree view inline; nothing else may run or load.
    csp = client.get("/sitemap.xml").headers["content-security-policy"]
    assert "style-src 'unsafe-inline'" in csp and "default-src 'none'" in csp and "script-src" not in csp
    assert "unsafe-inline" not in client.get("/").headers["content-security-policy"]
    assert "unsafe-inline" not in client.get("/robots.txt").headers["content-security-policy"]


def test_robots_points_to_sitemap(client, site_url):
    assert "Sitemap: https://status.example.com/sitemap.xml\n" in client.get("/robots.txt").text


def test_sitemap_lists_public_pages(admin, site_url):
    assert _urls(admin.get("/sitemap.xml")) == {"https://status.example.com/": None}

    admin.put("/api/admin/legal/imprint", json={"title": None, "content": "Jane Doe"})
    public = admin.post("/api/admin/monitors", json=MONITOR).json()["id"]
    hidden = admin.post("/api/admin/monitors", json={**MONITOR, "name": "Hidden", "is_public": False}).json()["id"]
    for mid in (public, hidden):
        record_result(mid, ProbeResult(False, None, None, "Connection refused"))
    incidents = admin.get("/api/status").json()["incidents"]["active"]
    assert len(incidents) == 1

    urls = _urls(admin.get("/sitemap.xml"))
    assert set(urls) == {
        "https://status.example.com/",
        "https://status.example.com/imprint",
        f"https://status.example.com/incidents/{incidents[0]['id']}",
    }
    assert all(v.endswith("Z") for k, v in urls.items() if k != "https://status.example.com/")

    # Posting an update moves the incident's lastmod forward.
    loc = f"https://status.example.com/incidents/{incidents[0]['id']}"
    before = urls[loc]
    res = admin.post(f"/api/admin/incidents/{incidents[0]['id']}/updates", json={"status": "update", "message": "Hi"})
    after = _urls(admin.get("/sitemap.xml"))[loc]
    assert after == res.json()["updates"][0]["created_at"] and after >= before


def test_site_url_falls_back_to_allowed_host():
    base = get_settings()
    assert dataclasses.replace(base, allowed_hosts=["*.example.com", "status.example.com"]).site_url == (
        "http://status.example.com"
    )
    assert dataclasses.replace(base, allowed_hosts=["status.example.com"], cookie_secure=True).site_url == (
        "https://status.example.com"
    )
    assert dataclasses.replace(base, allowed_hosts=[]).site_url is None
    explicit = dataclasses.replace(base, allowed_hosts=["a.example"], public_url="https://b.example/status")
    assert explicit.site_url == "https://b.example/status"


@pytest.mark.parametrize("value", ["status.example.com", "ftp://example.com", "https://", "https://x.example/?a=1"])
def test_public_url_validated(monkeypatch, value):
    monkeypatch.setenv("UPTIME_PUBLIC_URL", value)
    with pytest.raises(ValueError):
        _url("PUBLIC_URL")


def test_public_url_trailing_slash_stripped(monkeypatch):
    monkeypatch.setenv("UPTIME_PUBLIC_URL", "https://status.example.com/")
    assert _url("PUBLIC_URL") == "https://status.example.com"
