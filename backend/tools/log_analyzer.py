"""Log analyzer: failed-login bursts and top suspicious IPs in auth/nginx logs.

STUB: Role 4 implements this. Findings use the "log.*" keys in knowledge.json.
Uploads (.log/.txt, max 5 MB) are read into memory and never saved to disk.
"""

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from backend.auth import current_user
from backend.db import get_db
from backend.models import User

LABEL = "Log analyzer"
router = APIRouter()


@router.post("/log-analyzer")
def log_analyzer(
    file: UploadFile = File(...), user: User = Depends(current_user), db: Session = Depends(get_db)
):
    raise HTTPException(501, "Log analyzer is not implemented yet")
