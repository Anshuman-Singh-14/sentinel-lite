"""Shared Pydantic input types used by several routes."""

import ipaddress
import re
import unicodedata
from typing import Annotated

from pydantic import AfterValidator, EmailStr, StringConstraints

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


DISPLAY_NAME_PUNCTUATION = " .-'"


def check_display_name(value: str) -> str:
    """Trimmed; "" means "clear it". Letters in any language (with their accent marks),
    digits, spaces and . - ' only, so nothing odd ends up in an email."""
    value = value.strip()
    if len(value) > 50:
        raise ValueError("display name must be at most 50 characters")
    for char in value:
        # Unicode categories: L = letters, M = marks such as accents and Hindi vowel signs, Nd = digits.
        category = unicodedata.category(char)
        if not (category[0] in "LM" or category == "Nd" or char in DISPLAY_NAME_PUNCTUATION):
            raise ValueError("display name can only use letters, digits, spaces and . - '")
    return value


Hostname = Annotated[str, StringConstraints(max_length=253), AfterValidator(clean_host)]
Username = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]{3,32}$")]
Password = Annotated[str, StringConstraints(min_length=8), AfterValidator(check_password)]
# Lowercased, so Alice@Gmail.com and alice@gmail.com count as the same address.
Email = Annotated[EmailStr, AfterValidator(str.lower)]
# The name shown in emails instead of an admin's username. Empty clears it.
DisplayName = Annotated[str, StringConstraints(max_length=200), AfterValidator(check_display_name)]
