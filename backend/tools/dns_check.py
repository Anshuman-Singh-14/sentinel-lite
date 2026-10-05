"""DNS & email check: A, MX and TXT records, SPF and DMARC.

STUB: Role 2 implements this. Findings use the "dns.*" keys in knowledge.json.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.auth import current_user
from backend.db import get_db
from backend.models import User
from backend.validation import Hostname

LABEL = "DNS & email check"
router = APIRouter()


class DnsCheckRequest(BaseModel):
    domain: Hostname


@router.post("/dns-check")
def dns_check(body: DnsCheckRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    raise HTTPException(501, "DNS check is not implemented yet")
