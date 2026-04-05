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

    template_dir = Path("multi_agent_system/templates")
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
