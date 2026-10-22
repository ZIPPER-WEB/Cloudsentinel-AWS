from datetime import datetime, timezone
from html import escape
from pathlib import Path


def generate_html_report(findings, summary, region):
    """Generate a readable HTML report from CloudSentinel scan results."""

    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    severity_cards = ""
    for severity in ("critical", "high", "medium", "low", "informational"):
        count = summary.get(severity, 0)
        severity_cards += f"""
        <div class="card severity-{escape(severity)}">
            <h3>{escape(severity.title())}</h3>
            <p>{escape(str(count))}</p>
        </div>
        """

    findings_html = ""
    if findings:
        for finding in findings:
            severity = escape(str(finding.get("severity", "Unknown")))
            title = escape(str(finding.get("title", "Untitled finding")))
            resource_id = escape(str(finding.get("resource_id", "N/A")))
            description = escape(str(finding.get("description", "")))
            recommendation = escape(str(finding.get("recommendation", "")))

            findings_html += f"""
            <section class="finding">
                <div class="finding-heading">
                    <h3>{title}</h3>
                    <span class="severity-badge">{severity}</span>
                </div>
                <p><strong>Resource:</strong> <code>{resource_id}</code></p>
                <p>{description or "No description provided."}</p>
                <p><strong>Recommended action:</strong> {recommendation or "Review the resource configuration."}</p>
            </section>
            """
    else:
        findings_html = """
        <p class="empty">
            No findings were detected by the current analysis rules.
        </p>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudSentinel Security Report</title>
    <style>
        :root {{
            color-scheme: light;
            --blue: #2878f0;
            --text: #1d1d1f;
            --muted: #74747a;
            --border: #e8e8ed;
            --background: #f5f5f7;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            max-width: 1100px;
            margin: 36px auto;
            padding: 0 20px;
            background: var(--background);
            color: var(--text);
            line-height: 1.6;
        }}
        header {{
            background: linear-gradient(135deg, #ffffff, #edf4ff);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 30px;
        }}
        .eyebrow {{
            color: var(--blue);
            font-size: 12px;
            font-weight: 800;
            letter-spacing: 1.6px;
            text-transform: uppercase;
        }}
        header h1 {{
            margin: 8px 0;
            font-size: clamp(28px, 5vw, 42px);
            letter-spacing: -1.4px;
        }}
        .muted {{ color: var(--muted); }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
            gap: 14px;
            margin: 18px 0 30px;
        }}
        .card, .finding, .empty {{
            background: #fff;
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(25, 45, 85, .03);
        }}
        .card h3 {{ margin: 0; color: var(--muted); font-size: 14px; font-weight: 600; }}
        .card p {{ margin: 8px 0 0; font-size: 30px; font-weight: 800; letter-spacing: -1px; }}
        .severity-critical p {{ color: #b42318; }}
        .severity-high p {{ color: #dc4545; }}
        .severity-medium p {{ color: #b7791f; }}
        .severity-low p {{ color: #2878f0; }}
        .severity-informational p {{ color: #64748b; }}
        .finding {{ margin: 14px 0; overflow-wrap: anywhere; }}
        .finding-heading {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }}
        .finding h3 {{ margin: 0 0 10px; font-size: 17px; }}
        .severity-badge {{
            flex-shrink: 0;
            padding: 3px 9px;
            border-radius: 999px;
            background: #edf4ff;
            color: #245bb5;
            font-size: 12px;
            font-weight: 700;
        }}
        code {{ overflow-wrap: anywhere; }}
        .empty {{ padding: 24px; }}
        footer {{
            margin: 30px 0;
            padding-top: 18px;
            border-top: 1px solid var(--border);
            color: var(--muted);
            font-size: 13px;
        }}
        @media (max-width: 600px) {{
            body {{ margin: 18px auto; padding: 0 12px; }}
            header {{ padding: 22px; }}
            .finding-heading {{ flex-direction: column; }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="eyebrow">AWS Network Security &amp; Diagnostics</div>
        <h1>CloudSentinel</h1>
        <p class="muted">Network troubleshooting and security analysis report</p>
        <p><strong>Region:</strong> {escape(str(region))}</p>
        <p><strong>Generated:</strong> {escape(scan_time)}</p>
    </header>

    <h2>Scan summary</h2>
    <div class="cards">
        <div class="card">
            <h3>Total findings</h3>
            <p>{escape(str(summary.get("total", len(findings))))}</p>
        </div>
        {severity_cards}
    </div>

    <h2>Findings</h2>
    {findings_html}

    <footer>
        Generated locally by CloudSentinel. Findings reflect only the checks implemented
        in this version and should be validated before making infrastructure changes.
    </footer>
</body>
</html>
"""

    reports_dir = Path(__file__).resolve().parent
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = reports_dir / f"cloudsentinel_report_{timestamp}.html"
    report_path.write_text(html_content, encoding="utf-8")
    return report_path
