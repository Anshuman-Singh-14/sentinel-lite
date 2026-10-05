"""Shared Pydantic input types used by several routes."""

import ipaddress
import re
from typing import Annotated

from pydantic import AfterValidator, StringConstraints

LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def clean_host(value: str) -> str:
    """Accept an IPv4 address or a DNS hostname like "example.com". Returns it lowercased."""
    value = value.strip().lower().rstrip(".")
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        pass
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or not all(LABEL.match(label) for label in labels):
        raise ValueError("enter a hostname like example.com or an IPv4 address")
    return value


def check_password(value: str) -> str:
    # bcrypt only uses the first 72 bytes, so longer passwords are refused instead of cut.
    if len(value.encode()) > 72:
        raise ValueError("password must be at most 72 bytes")
    return value


Hostname = Annotated[str, StringConstraints(max_length=253), AfterValidator(clean_host)]
Username = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]{3,32}$")]
Password = Annotated[str, StringConstraints(min_length=8), AfterValidator(check_password)]
