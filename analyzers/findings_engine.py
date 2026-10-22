def combine_findings(*finding_groups):
    """Combine findings from multiple analyzers into one list."""

    all_findings = []

    for group in finding_groups:
        all_findings.extend(group)

    return all_findings


def summarize_findings(findings):
    """Summarize findings by severity."""

    summary = {
        "total": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "").lower()

        if severity in summary and severity != "total":
            summary[severity] += 1

    return summary