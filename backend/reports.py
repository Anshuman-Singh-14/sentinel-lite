"""Scan history and exports (CSV and a print-friendly HTML page).

STUB: Role 4 implements these.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.auth import current_user
from backend.db import get_db
from backend.models import User

router = APIRouter(prefix="/api/scans", tags=["reports"])

NOT_YET = HTTPException(501, "Not implemented yet")


@router.get("")
def list_scans(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """The logged-in user's scans, newest first."""
    raise NOT_YET


@router.get("/{scan_id}")
def get_scan(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    raise NOT_YET


@router.get("/{scan_id}/export.csv")
def export_csv(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    raise NOT_YET


@router.get("/{scan_id}/report")
def export_html(scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """A standalone HTML page the user can print or "Save as PDF"."""
    raise NOT_YET
