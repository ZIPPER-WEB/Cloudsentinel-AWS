from analyzers.findings_engine import (
    combine_findings,
    summarize_findings,
)


def test_combine_findings():
    security_findings = [
        {"severity": "HIGH", "title": "Public SSH"},
    ]

    route_findings = [
        {"severity": "MEDIUM", "title": "Blackhole route"},
    ]

    result = combine_findings(
        security_findings,
        route_findings,
    )

    assert len(result) == 2


def test_summarize_findings():
    findings = [
        {"severity": "HIGH"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
        {"severity": "LOW"},
    ]

    result = summarize_findings(findings)

    assert result["total"] == 4
    assert result["high"] == 2
    assert result["medium"] == 1
    assert result["low"] == 1
    assert result["critical"] == 0