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
    assert "<li>First step</li>" in result
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
