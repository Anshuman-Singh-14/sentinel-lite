"""Website check: HTTPS, certificate expiry and 6 security headers.

STUB: Role 2 implements this. Findings use the "web.*" keys in knowledge.json.
Only admin-approved targets: call guard.check_target() before connecting.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.auth import current_user
from backend.db import get_db
from backend.models import User
from backend.validation import Hostname

LABEL = "Website check"
router = APIRouter()


class WebCheckRequest(BaseModel):
    target: Hostname


@router.post("/web-check")
def web_check(body: WebCheckRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    raise HTTPException(501, "Website check is not implemented yet")
