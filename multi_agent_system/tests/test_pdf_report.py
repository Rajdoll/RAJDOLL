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
        agents=[{"agent_name": "InputValidationAgent", "status": "completed", "duration": "5m", "note": ""}],
        scope_whitelist=[], oos_findings=None, scan_timing=None,
        llm_model="test-model",
        agent_count=14,
        wstg_all_categories={
            "WSTG-INFO": "Information Gathering",
            "WSTG-INPV": "Input Validation",
        },
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


def test_template_receives_new_vars():
    """WSTG_ALL_CATEGORIES is importable and template renders without error with new vars."""
    from api.routes.pdf_report import WSTG_ALL_CATEGORIES
    assert len(WSTG_ALL_CATEGORIES) == 11
    assert "WSTG-INPV" in WSTG_ALL_CATEGORIES
    assert "WSTG-ATHN" in WSTG_ALL_CATEGORIES


def test_wstg_coverage_shows_all_11_categories():
    """All 11 WSTG categories appear in rendered HTML, including those with 0 findings."""
    from pathlib import Path
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from api.routes.pdf_report import _md, WSTG_ALL_CATEGORIES

    template_path = Path(__file__).resolve().parent.parent / "templates" / "report.html.j2"
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["md"] = _md

    fake_finding = {
        "id": 1, "ref": "RAJDOLL-0001", "category": "WSTG-INPV",
        "title": "XSS", "severity": "HIGH", "agent_name": "InputValidationAgent",
        "evidence": "xss", "explanation": "", "remediation": "",
        "cwe_id": "", "wstg_id": "WSTG-INPV-07", "cvss_score_v4": None,
        "references": [], "enrichment_source": "fallback",
    }
    html = env.get_template(template_path.name).render(
        job_id=1, target="http://example.com",
        scan_date="2026-05-23", scan_duration="1h",
        total_findings=1, final_analysis="",
        findings=[fake_finding], top_findings=[fake_finding],
        sev_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        wstg_categories={"WSTG-INPV": 1},
        enrichment_stats={"static_kb": 0, "llm": 0, "fallback": 1},
        agents=[{"agent_name": "InputValidationAgent", "status": "completed",
                 "duration": "5m", "note": ""}],
        scope_whitelist=[], oos_findings=None, scan_timing=None,
        llm_model="qwen/qwen3-4b", agent_count=14,
        wstg_all_categories=WSTG_ALL_CATEGORIES,
    )
    for cat_id in WSTG_ALL_CATEGORIES:
        assert cat_id in html, f"Missing category: {cat_id}"
    assert "Not detected" in html
    assert "Detected" in html


def test_findings_index_table_present():
    """Findings Index table appears before finding cards with ref, title, severity, wstg, agent."""
    from pathlib import Path
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from api.routes.pdf_report import _md, WSTG_ALL_CATEGORIES

    template_path = Path(__file__).resolve().parent.parent / "templates" / "report.html.j2"
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["md"] = _md

    fake_finding = {
        "id": 1, "ref": "RAJDOLL-0001", "category": "WSTG-INPV",
        "title": "SQL Injection via login", "severity": "CRITICAL",
        "agent_name": "InputValidationAgent", "evidence": "payload",
        "explanation": "", "remediation": "",
        "cwe_id": "CWE-89", "wstg_id": "WSTG-INPV-05",
        "cvss_score_v4": 9.3, "references": [], "enrichment_source": "static_kb",
    }
    html = env.get_template(template_path.name).render(
        job_id=1, target="http://example.com",
        scan_date="2026-05-23", scan_duration="1h",
        total_findings=1, final_analysis="",
        findings=[fake_finding], top_findings=[fake_finding],
        sev_counts={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        wstg_categories={"WSTG-INPV": 1},
        enrichment_stats={"static_kb": 1, "llm": 0, "fallback": 0},
        agents=[{"agent_name": "InputValidationAgent", "status": "completed",
                 "duration": "5m", "note": ""}],
        scope_whitelist=[], oos_findings=None, scan_timing=None,
        llm_model="qwen/qwen3-4b", agent_count=14,
        wstg_all_categories=WSTG_ALL_CATEGORIES,
    )
    assert "Findings Index" in html
    assert "RAJDOLL-0001" in html
    assert "SQL Injection via login" in html
    assert "WSTG-INPV-05" in html
    assert "InputValidationAgent" in html


def test_severity_group_headers_in_findings():
    """Severity group headers appear before each group of finding cards."""
    from pathlib import Path
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from api.routes.pdf_report import _md, WSTG_ALL_CATEGORIES

    template_path = Path(__file__).resolve().parent.parent / "templates" / "report.html.j2"
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["md"] = _md

    findings = [
        {"id": 1, "ref": "RAJDOLL-0001", "category": "WSTG-INPV", "title": "SQLi",
         "severity": "CRITICAL", "agent_name": "InputValidationAgent",
         "evidence": "e", "explanation": "", "remediation": "",
         "cwe_id": "", "wstg_id": "WSTG-INPV-05", "cvss_score_v4": None,
         "references": [], "enrichment_source": "fallback"},
        {"id": 2, "ref": "RAJDOLL-0002", "category": "WSTG-ATHN", "title": "Weak creds",
         "severity": "HIGH", "agent_name": "AuthenticationAgent",
         "evidence": "e", "explanation": "", "remediation": "",
         "cwe_id": "", "wstg_id": "WSTG-ATHN-07", "cvss_score_v4": None,
         "references": [], "enrichment_source": "fallback"},
    ]
    html = env.get_template(template_path.name).render(
        job_id=1, target="http://example.com",
        scan_date="2026-05-23", scan_duration="1h",
        total_findings=2, final_analysis="",
        findings=findings, top_findings=findings,
        sev_counts={"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        wstg_categories={"WSTG-INPV": 1, "WSTG-ATHN": 1},
        enrichment_stats={"static_kb": 0, "llm": 0, "fallback": 2},
        agents=[{"agent_name": "InputValidationAgent", "status": "completed",
                 "duration": "5m", "note": ""}],
        scope_whitelist=[], oos_findings=None, scan_timing=None,
        llm_model="qwen/qwen3-4b", agent_count=14,
        wstg_all_categories=WSTG_ALL_CATEGORIES,
    )
    assert "Critical Findings" in html
    assert "High Findings" in html


def test_appendix_shows_dynamic_agent_count_and_llm_model():
    """Appendix A/C show llm_model and agent_count from template vars, not hardcoded."""
    from pathlib import Path
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    from api.routes.pdf_report import _md, WSTG_ALL_CATEGORIES

    template_path = Path(__file__).resolve().parent.parent / "templates" / "report.html.j2"
    env = Environment(
        loader=FileSystemLoader(str(template_path.parent)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["md"] = _md

    fake_finding = {
        "id": 1, "ref": "RAJDOLL-0001", "category": "WSTG-INPV", "title": "XSS",
        "severity": "HIGH", "agent_name": "InputValidationAgent",
        "evidence": "e", "explanation": "", "remediation": "",
        "cwe_id": "", "wstg_id": "WSTG-INPV-07", "cvss_score_v4": None,
        "references": [], "enrichment_source": "llm",
    }
    html = env.get_template(template_path.name).render(
        job_id=1, target="http://example.com",
        scan_date="2026-05-23", scan_duration="1h",
        total_findings=1, final_analysis="",
        findings=[fake_finding], top_findings=[fake_finding],
        sev_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        wstg_categories={"WSTG-INPV": 1},
        enrichment_stats={"static_kb": 0, "llm": 1, "fallback": 0},
        agents=[{"agent_name": "InputValidationAgent", "status": "completed",
                 "duration": "5m", "note": ""}],
        scope_whitelist=[], oos_findings=None, scan_timing=None,
        llm_model="my-custom-model-7b",
        agent_count=99,
        wstg_all_categories=WSTG_ALL_CATEGORIES,
    )
    assert "my-custom-model-7b" in html
    assert "99" in html
    assert "Qwen 3-4B" not in html
