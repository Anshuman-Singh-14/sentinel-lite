"""The explain layer: turns finding keys into explained findings, and saves scans.

Tools never write explanation text themselves. They report a key such as
"web.missing_hsts" and this module looks up the title, severity, explanation and
fix in knowledge.json, so all the wording lives in one file.
"""

import json
from pathlib import Path

from sqlalchemy.orm import Session

from backend.models import Scan, User

KNOWLEDGE_FILE = Path(__file__).resolve().parent / "knowledge.json"
KNOWLEDGE: dict[str, dict] = json.loads(KNOWLEDGE_FILE.read_text(encoding="utf-8"))
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def make_finding(key: str, **details) -> dict:
    """An explained finding. `details` holds facts for this case, e.g. port=23."""
    entry = KNOWLEDGE[key]  # a KeyError here means the key is missing from knowledge.json
    return {
        "key": key,
        "title": entry["title"],
        "severity": entry["severity"],
        "explanation": entry["explanation"],
        "fix": entry["fix"],
        "details": details,
    }


def scan_to_dict(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "tool": scan.tool,
        "target": scan.target,
        "created_at": scan.created_at.isoformat(),
        "summary": scan.summary,
        "findings": scan.findings,
    }


def save_scan(db: Session, user: User, tool: str, target: str, summary: dict, findings: list) -> dict:
    """Store a finished scan (most severe findings first) and return it as the API response."""
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])
    scan = Scan(user_id=user.id, tool=tool, target=target, summary=summary, findings=findings)
    db.add(scan)
    db.commit()
    return scan_to_dict(scan)
