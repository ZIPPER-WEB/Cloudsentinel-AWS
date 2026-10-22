import json
from datetime import datetime, timezone
from pathlib import Path


def generate_json_report(findings, summary, region):
    """Generate a JSON report from CloudSentinel scan results."""

    report = {
        "project": "CloudSentinel",
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "region": region,
        "summary": summary,
        "findings": findings,
    }

    reports_dir = Path(__file__).resolve().parent
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = reports_dir / f"cloudsentinel_report_{timestamp}.json"

    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=4, default=str)

    return report_path