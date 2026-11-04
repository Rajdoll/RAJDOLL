"""CVSS v3.1 base scores (FIRST specification) and the vulnerability catalog (BSD 6.1)."""

import pytest

from rajdoll.core import cvss
from rajdoll.data import vuln_types


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ],
)
def test_base_scores_match_the_specification(vector: str, score: float) -> None:
    assert cvss.score31(vector) == score


def test_roundup_avoids_floating_point_artefacts() -> None:
    assert cvss._roundup(4.0000001) == 4.0  # an artefact of float arithmetic
    assert cvss._roundup(4.00001) == 4.1
    assert cvss._roundup(4.0) == 4.0
    assert cvss._roundup(4.02) == 4.1


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
    ],
)
def test_invalid_vectors_are_rejected(vector: str) -> None:
    with pytest.raises(cvss.CvssError):
        cvss.score31(vector)


@pytest.mark.parametrize(
    ("score", "severity"),
    [(10.0, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"), (6.9, "medium"),
     (4.0, "medium"), (3.9, "low"), (0.1, "low"), (0.0, "info")],
)  # fmt: skip
def test_severity_mapping(score: float, severity: str) -> None:
    assert cvss.severity(score) == severity


def test_catalog_entries_are_complete() -> None:
    expected = {
        "sqli": "critical",
        "xss_reflected": "medium",
        "cmdi": "critical",
        "ssti": "critical",
        "ssrf": "high",
    }
    for key, severity in expected.items():
        kind = vuln_types.get(key)
        assert kind.key == key
        assert cvss.severity(cvss.score31(kind.cvss31)) == severity
        assert kind.wstg_id.startswith("WSTG-INPV-")
        assert kind.cwe_id.startswith("CWE-")
        assert kind.title and kind.description and kind.impact and kind.recommendation
        assert kind.references
    with pytest.raises(KeyError):
        vuln_types.get("tidak_ada")
