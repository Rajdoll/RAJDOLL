"""Unit tests for pdf_report helpers — no Docker, no WeasyPrint required."""
import pytest


def test_md_converts_bold():
    from api.routes.pdf_report import _md
    result = str(_md("**SQL Injection** found"))
    assert "<strong>SQL Injection</strong>" in result
    assert "**" not in result


def test_md_converts_heading():
    from api.routes.pdf_report import _md
    result = str(_md("## Risk Assessment"))
    assert "<h2>" in result
    assert "##" not in result


def test_md_converts_ordered_list():
    from api.routes.pdf_report import _md
    result = str(_md("1. First step\n2. Second step"))
    assert "<ol>" in result
    assert "<li>" in result
    assert "First step" in result
    assert "1." not in result


def test_md_returns_empty_string_for_none():
    from api.routes.pdf_report import _md
    assert str(_md(None)) == ""
    assert str(_md("")) == ""


def test_md_returns_markup_instance():
    from api.routes.pdf_report import _md
    from markupsafe import Markup
    result = _md("hello")
    assert isinstance(result, Markup)


def test_md_nl2br_converts_newlines():
    from api.routes.pdf_report import _md
    result = str(_md("line one\nline two"))
    assert "<br" in result   # nl2br extension converts \n to <br />


def test_md_filter_registered_on_env():
    """Verify _md is registered as a Jinja2 filter so templates can use | md."""
    from pathlib import Path
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from api.routes.pdf_report import _md

    template_dir = Path(__file__).resolve().parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["md"] = _md
    assert "md" in env.filters
    # Verify filter works inside a template expression
    tmpl = env.from_string("{{ text | md }}")
    result = tmpl.render(text="**bold**")
    assert "<strong>bold</strong>" in result


def test_template_renders_markdown_fields():
    """Render report.html.j2 with fake data and verify markdown is converted."""
    from pathlib import Path
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from api.routes.pdf_report import _md

    template_path = Path(__file__).resolve().parent.parent / "templates" / "report.html.j2"
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["md"] = _md

    fake_finding = {
        "id": 1, "ref": "RAJDOLL-0001",
        "category": "WSTG-INPV", "title": "SQL Injection",
        "severity": "CRITICAL", "agent_name": "InputValidationAgent",
        "evidence": "payload: ' OR 1=1",
        "explanation": "**SQL injection** allows authentication bypass.\n\n## Impact\nCritical.",
        "remediation": "1. Use parameterized queries.\n2. Validate all inputs.",
        "cwe_id": "CWE-89", "wstg_id": "WSTG-INPV-05",
        "cvss_score_v4": 9.3, "references": ["https://owasp.org"],
        "enrichment_source": "fallback",
    }
    html = env.get_template(template_path.name).render(
        job_id=1, target="http://juice-shop:3000",
        scan_date="2026-04-05 00:00 UTC", scan_duration="1h 5m",
        total_findings=1, final_analysis="## Summary\n**Critical** findings detected.",
        findings=[fake_finding], top_findings=[fake_finding],
        sev_counts={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        wstg_categories={"WSTG-INPV": 1}, enrichment_stats={"static_kb": 0, "llm": 0, "fallback": 1},
        agents=[{"agent_name": "InputValidationAgent", "status": "completed", "duration": "5m"}],
    )

    # markdown was converted — no raw markers in output
    assert "**SQL injection**" not in html
    assert "##" not in html
    assert "<strong>SQL injection</strong>" in html
    assert "<ol>" in html          # remediation numbered list rendered
    assert "<li>" in html
    assert "Use parameterized" in html

    # fallback badge shows GEN not —
    assert '<span class="src-fallback">GEN</span>' in html
