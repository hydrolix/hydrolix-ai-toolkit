from __future__ import annotations

from tests.report_engine_helpers import *

def test_threat_hunt_registered_and_renders_markdown(tmp_path):
    import render_report
    from report_engine.contexts import REPORT_TYPE_REGISTRY

    assert "threat_hunt" in REPORT_TYPE_REGISTRY
    assert "threat_hunt" in render_report.REPORT_TYPES
    wrapper = json.loads(
        (FIXTURES / "threat_hunt_registered_wrapper.json").read_text(encoding="utf-8")
    )
    path = tmp_path / "threat_hunt.json"
    path.write_text(json.dumps(wrapper), encoding="utf-8")
    md = _render(path, "--format", "markdown")
    assert "Report type: `threat_hunt`" in md
    assert md.index("## Campaign Summary") < md.index("## Scraper Leads")
    assert md.index("## UA Families") < md.index("## Scraper Leads")
    assert "ua\\-family\\-1" in md
    assert "Recommendation: **Tier 3** - Campaign Watchlist Or Challenge" in md
    assert md.count("Recommendation: **Tier 3** - Campaign Watchlist Or Challenge") == 1
    assert "## Known Crawler And Infrastructure Traffic" in md
    assert "Googlebot/2\\.1" in md
    assert "## Bot Manager Context" in md
    assert "Bot Manager context is operational enrichment" in md
    assert "Action class mix:" in md
    assert "deny" in md
    assert "Bot Manager exact-UA context: 900 requests" in md
    assert "Evidence: \n" not in md
    assert "Evidence: \r\n" not in md
    assert "Part of UA family ua\\-family\\-1" in md
    assert "2 members also appear in campaign\\-1" in md
    assert "links to CatalogScraper" in md
    assert "3 shared IPs" in md
    assert "path similarity 0\\.91" in md
    assert "Part of campaign\\-1" in md
    assert "Campaign surface: **Focused Api Surface**" in md
    assert "Impact: Share of total 24.0%; response body unavailable (unavailable of response bytes)" in md
    assert "Share of total bytes" not in md
    assert "IMPACT: 2.4K requests (24.0% of window total) · 500.0M response body (50.0% of response bytes)" in md
    assert "Campaign endpoint evidence" in md
    assert "## Scraper Leads" in md
    assert "CatalogScraper" in md
    assert "Surface coverage: **Focused**" in md
    assert "Endpoint evidence: **Not Available**" in md
    assert "UA plausibility: **Confirmed**" in md
    assert "UA plausibility anomaly confirmed" in md
    assert "Future\\-dated Chrome/149" in md
    assert "Timing status" in md
    assert "Metronome" in md
    assert "CV 0\\.00" in md
    assert "Background-rate caveats: Endpoint Targeting 12.0% (moderate)" in md
    assert "Ua Ip Fanout unavailable" not in md
    assert "Fan-out shelf life" in md
    assert "Case against / missing evidence" in md
    assert "## Scraper Pattern Context" in md
    assert "Direct\\-to\\-data/API focus" in md
    assert "Boxy or interval cadence" in md
    assert "UA impersonation / rotation" in md
    assert "Distributed fan\\-out" in md
    assert "[OWASP OAT\\-011 Scraping](https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-011_Scraping)" in md
    assert "not classification evidence" in md
    assert "/api/catalog" in md
    assert "Raw actor user-agent exports were not supplied." in md
    assert "operator" in md
    assert "malicious intent" not in md.lower()

    html = _render(path)
    assert 'class="report-header"' not in html
    assert '<div class="thr">' in html
    assert 'class="thr-header header-titles"' in html
    assert "Hydrolix" in html
    assert "2026-05-01T00:00:00Z to 2026-05-02T00:00:00Z" in html
    assert 'data-hx-export-all' in html
    assert 'data-hx-drawer-toggle' in html
    assert '<body data-hx-drawer-host data-hx-drawer-state="collapsed">' in html
    assert "⇰ Show IOCs" in html
    assert "window.HX.setDrawer(false);" in html
    assert "data:image/svg+xml;base64" in html
    assert 'static/reports/threat-hunt.css' not in html
    assert '<script src="static/kit.js"></script>' not in html
    assert "[hidden] { display: none !important; }" in html
    assert ".hx-drawer[hidden]," in html
    assert ".hx-rail[hidden] { display: none !important; }" in html
    assert 'body[data-hx-drawer-state="collapsed"] .thr-body' in html
    assert 'id="verdict" class="thr-verdict"' in html
    assert '<div class="thr-eyebrow">Verdict</div>' not in html
    assert '<span class="thr-h1-sub"> · Threat Hunt</span>' in html
    assert "scraper coordination hunt" not in html
    assert 'class="thr-lede-grid dek" aria-label="Threat hunt topline"' in html
    assert html.index("What the hunt found") < html.index("Hunt impact")
    assert html.index("Impact of those findings") < html.index("Hunt impact")
    assert html.index("Recommended actions") < html.index("Hunt impact")
    assert "Hunt-scoped findings account for" in html
    assert "Recommended queue:" in html
    assert 'class="hx-ladder"' in html
    assert 'class="thr-hunt-impact"' in html
    assert 'class="thr-impact-strip"' not in html
    assert 'id="actions" class="thr-section"' in html
    assert "Response queue" in html
    assert "Impact-backed response candidates" in html
    assert "Monitor / validate before enforcement" in html
    assert "Actions are grouped by confidence boundary" in html
    assert "Do not treat them as part of the Hunt impact total." in html
    assert 'id="leads" class="thr-section"' in html
    assert 'id="campaign" class="thr-section"' in html
    assert 'id="infra" class="thr-section"' in html
    assert 'id="evidence" class="thr-section"' in html
    assert '<aside class="hx-drawer" data-hx-drawer hidden>' in html
    assert 'class="hx-rail"' in html
    assert '<aside class="hx-rail" role="button" tabindex="0"' in html
    assert "data-hx-drawer-collapse" in html
    assert "data-hx-rail-expand" in html
    assert re.search(
        r'<div class="hx-drawer-list" data-hx-drawer-panel="ua"[^>]*>',
        html,
    )
    assert re.search(
        r'<div class="hx-drawer-list" data-hx-drawer-panel="ep"[^>]*hidden',
        html,
    )
    assert re.search(
        r'<div class="hx-drawer-list" data-hx-drawer-panel="ip"[^>]*hidden',
        html,
    )
    assert 'id="leads"' in html
    assert "ua-family-1" in html
    assert "campaign-1" in html
    assert "CatalogScraper/1.0" in html
    assert "ApiProbe/1.0" in html
    assert "ApiProbe/2.0" in html
    assert "/api/:slug" in html
    assert "/api/catalog" in html
    assert "24.0% of window" in html
    assert "Hunt impact" in html
    assert "Response body" in html
    assert "Akamai-billed" in html
    assert "Hydrolix log ingest" in html
    assert "total bytes" not in html.lower()
    assert "UA plausibility" in html
    assert "Confirmed" in html
    assert "Ua Ip Fanout unavailable" not in html
    assert "120.0x (+1.2K)" in html
    assert "Observed" in html
    assert "Direct-to-data/API focus" in html
    assert "https://www.f5.com/labs/articles/how-to-identify-and-stop-scrapers" in html
    assert "not classification evidence" in html
    assert "Not established" in html
    assert "Operator identity" in html
    assert "Malicious intent" in html
    assert "Cross-customer reuse" in html
    assert "user_agents" in html
    assert "example.com" not in html.lower()
    assert "origin-capacity" not in html
    assert "cache-hit" not in html
    assert "Bot Manager context is operational enrichment" not in html

    bundle_out = tmp_path / "bundle" / "threat_hunt.html"
    bundle_out.parent.mkdir()
    subprocess.run(
        [
            "uv",
            "run",
            "--quiet",
            str(RENDER_PY),
            "--artifact",
            str(path),
            "--out",
            str(bundle_out),
            "--asset-mode",
            "bundle",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    bundle_html = bundle_out.read_text()
    assert '<link rel="stylesheet" href="static/tokens/brand.css" />' in bundle_html
    assert '<script src="static/kit.js"></script>' in bundle_html
    assert "data:image/svg+xml;base64" not in bundle_html
    assert (bundle_out.parent / "static/reports/threat-hunt.css").exists()
    assert (bundle_out.parent / "static/components/_kit.css").exists()
    assert (bundle_out.parent / "static/kit.js").exists()
    assert (bundle_out.parent / "assets/hydrolix-light.svg").exists()
    assert (
        "[hidden] { display: none !important; }"
        in (bundle_out.parent / "static/components/_kit.css").read_text()
    )
    kit_css = (bundle_out.parent / "static/components/_kit.css").read_text()
    assert ".hx-drawer[hidden]," in kit_css
    assert ".hx-rail[hidden] { display: none !important; }" in kit_css
    report_css = (bundle_out.parent / "static/reports/threat-hunt.css").read_text()
    assert 'body[data-hx-drawer-state="collapsed"] .thr-body' in report_css

    rejected = subprocess.run(
        [
            "uv",
            "run",
            "--quiet",
            str(RENDER_PY),
            "--artifact",
            str(path),
            "--out",
            str(tmp_path / "bad.md"),
            "--format",
            "markdown",
            "--asset-mode",
            "bundle",
        ],
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 1
    assert "--asset-mode bundle is only supported for screen HTML output" in rejected.stderr

    print_html = _render(path, "--profile", "print")
    assert 'data-pdf-layout="fixed-letter"' in print_html
    assert "HYDROLIX · BOTINSIGHTS" in print_html
    assert '<div class="hero pf-xl"' in print_html
    assert "Assessment summary" in print_html
    assert "Coordinated forged-UA operation consistent with Rate Limit Evasion" in print_html
    assert "Hunt Impact" in print_html
    assert "Finding share" in print_html
    assert "60.0% of window traffic" in print_html
    assert "campaign-1" in print_html
    assert "24.0% · 2.4K requests · 500.0 MB" in print_html
    assert "UA family" in print_html
    assert "36.0% · 3.6K requests" in print_html
    assert "Shares use total window traffic as the denominator" in print_html
    assert "Delta vs baseline" in print_html
    assert "120.0x (+1.2K)" in print_html
    assert print_html.count('<section class="page') == 6
    assert "01 Cover" in print_html
    assert "02 Story" in print_html
    assert "03 Recommended actions" in print_html
    assert "04 Evidence shape" in print_html
    assert "05 Scraper leads" in print_html
    assert "06 ATT&amp;CK · Methodology" in print_html
    assert "Threat Hunt Story" in print_html
    assert "Primary finding" in print_html
    assert "campaign-1 represents 24.0% of all Local traffic in this window" not in print_html
    assert "Secondary finding" in print_html
    assert "Independent leads" in print_html
    assert "What the hunt found" in print_html
    assert "ua-family-1" in print_html
    assert "147-149; 3 versions" in print_html
    assert "No independent high-priority leads outside campaign or UA-family groupings." in print_html
    assert "02 Analyst Assessment" not in print_html
    assert "Analyst Assessment · High confidence" not in print_html
    assert "Finding <b>01</b>" not in print_html
    assert "03 Findings" not in print_html
    assert "04 Evidence shape" in print_html
    assert "Findings and evidence boundaries" in print_html
    assert "Hunt Findings" in print_html
    assert "Evidence Boundaries" in print_html
    assert "Bottom line: the threat-hunt findings account for" in print_html
    assert "Pattern context" in print_html
    assert "Direct-to-data/API focus" in print_html
    assert "OWASP OAT-011 Scraping: https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-011_Scraping" in print_html
    assert "Trajectory: traffic share" in print_html
    assert "response-body bytes" in print_html
    assert "No dollar, origin-capacity, or cache-hit impact is shown" in print_html
    assert "campaign-1" in print_html
    assert "2 members" in print_html
    assert "Synchronized" in print_html
    assert "Focused Api Surface" in print_html
    assert "Campaigns</span><span class=\"value\">1 campaign" in print_html
    assert "Scraper leads</span><span class=\"value\">1 lead" in print_html
    assert "Campaign timing pattern</span><span class=\"value\">Synchronized" in print_html
    assert "Campaign surface</span><span class=\"value\">Focused Api Surface" in print_html
    assert "Temporal Regularity" in print_html
    assert "UA Anomaly" in print_html
    assert "Automation Signature" in print_html
    assert "Coordinated Activity" in print_html
    assert "Operator identity" in print_html
    assert "Malicious intent" in print_html
    assert "Cross-customer reuse" in print_html
    assert "Not established" in print_html
    assert "Partial" in print_html
    assert "Campaigns</span></div>" not in print_html
    assert "Leads</span></div>" not in print_html
    assert "Campaigns → Leads → Timing → Boundaries" not in print_html
    assert 'class="timeline"' not in print_html
    assert "Where they aimed" not in print_html
    assert "Score &amp; availability" not in print_html
    assert "Recommended Actions" in print_html
    assert "Mozilla/5.0 (Linux; Android" not in print_html
    assert "Evidence 1" not in print_html
    assert "2 lead targets" in print_html
    assert "IMPACT: 300 requests (3.0% of window total) · 30.0M response body (3.0% of response bytes)" in print_html
    assert "of window total" in print_html
    assert "of response bytes" in print_html
    assert print_html.count("Challenge Or Block Ua") == 1
    assert "Rate Limit Evasion · confidence 0.78" in print_html
    assert "Challenge campaign members and watch for displacement." in print_html
    assert "Bot Manager context:" in print_html
    assert "top action deny" in print_html
    assert "Known crawler and infrastructure traffic" in print_html
    assert "Googlebot/2.1" in print_html
    assert 'data-campaign-member="true" data-campaign-id="campaign-1"' in print_html
    assert "Classification &amp; edge" not in print_html
    assert "Validate current Bot Manager/SIEM coverage before enforcement" not in print_html
    assert "Browser UA age" not in print_html
    assert "No browser-age enrichment supplied." not in print_html
    assert "T1498, T1190, HDX-BOT-03" in print_html
    assert "ATT&amp;CK · Methodology" in print_html
    assert "Analyses included" in print_html
    assert "Traffic and byte-share impact" in print_html
    assert "Identifies which findings consume the largest share of total requests and bytes" in print_html
    assert "Baseline trajectory comparison" in print_html
    assert "Campaign linkage and coordination" in print_html
    assert "UA plausibility and family rotation" in print_html
    assert "Endpoint, fan-out, and timing evidence" in print_html
    assert "Evidence-boundary review" in print_html
    assert "bot_threat_hunt.v3" in print_html
    assert "Ua Ip Fanout unavailable" not in print_html
