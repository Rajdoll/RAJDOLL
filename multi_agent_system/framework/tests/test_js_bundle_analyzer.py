from pathlib import Path

import httpx
import pytest

from multi_agent_system.framework.js_bundle_analyzer import JSBundleAnalyzer


def test_analyzer_constructs():
    analyzer = JSBundleAnalyzer()
    assert analyzer.cache_path.parent.exists() or analyzer.cache_path.parent.name == "data"
