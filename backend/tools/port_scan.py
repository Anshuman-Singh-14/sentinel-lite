"""Port scanner: TCP connect scan of common ports or a custom list (max 100).

STUB: Role 2 implements this. Findings use the "port.*" keys in knowledge.json.
Only admin-approved targets: call guard.check_target() before connecting.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.auth import current_user
from backend.db import get_db
from backend.models import User
from backend.validation import Hostname

LABEL = "Port scan"
router = APIRouter()


class PortScanRequest(BaseModel):
    target: Hostname
    # None means "scan the common ports list"
    ports: list[Annotated[int, Field(ge=1, le=65535)]] | None = Field(
        default=None, min_length=1, max_length=100
    )


@router.post("/port-scan")
def port_scan(body: PortScanRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    raise HTTPException(501, "Port scan is not implemented yet")
