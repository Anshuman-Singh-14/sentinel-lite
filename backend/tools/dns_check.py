"""DNS & email check: A, MX and TXT records, SPF and DMARC.

SPF (a TXT record starting "v=spf1") lists the servers allowed to send mail for
the domain. DMARC (a TXT record at _dmarc.<domain>) tells receivers what to do
with mail that fails that check. Without them, anyone can forge the domain's email.
"""

import dns.exception
import dns.resolver
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend import guard
from backend.auth import current_user
from backend.db import get_db
from backend.models import User
from backend.results import make_finding, save_scan
from backend.validation import Hostname

LABEL = "DNS & email check"
DNS_TIMEOUT = 3  # seconds per lookup
DMARC_POLICIES = ("none", "quarantine", "reject")

router = APIRouter()

# Ask public resolvers directly (Cloudflare, then Google). They show what the rest of
# the internet sees, and they work even when this computer's DNS settings point at
# a VPN or office server that dnspython can't reach.
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
resolver.timeout = 1.5  # per server, so the second one gets a turn within DNS_TIMEOUT
resolver.lifetime = DNS_TIMEOUT


class DnsCheckRequest(BaseModel):
    domain: Hostname


def lookup(name: str, record_type: str) -> list[str]:
    """Records of one type as text. An empty list if the name or record doesn't exist."""
    try:
        answer = resolver.resolve(name, record_type)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    if record_type == "TXT":
        # A TXT record can be split into several quoted strings; join them back together.
        return [b"".join(record.strings).decode(errors="replace") for record in answer]
    if record_type == "MX":
        return [f"{record.preference} {record.exchange.to_text(omit_final_dot=True)}" for record in answer]
    return [record.to_text() for record in answer]


def check_spf(txt_records: list[str]) -> list[dict]:
    spf = [record for record in txt_records if record.lower().startswith("v=spf1")]
    if not spf:
        return [make_finding("dns.spf_missing")]
    if len(spf) > 1:
        return [make_finding("dns.spf_multiple", records=spf)]
    terms = spf[0].lower().split()
    all_terms = [term for term in terms if term.lstrip("+-~?") == "all"]
    if not all_terms:
        return [make_finding("dns.spf_no_all", record=spf[0])]
    if all_terms[-1] in ("all", "+all"):
        return [make_finding("dns.spf_allows_all", record=spf[0])]
    return []  # -all, ~all or ?all


def parse_tags(record: str) -> dict[str, str]:
    """'v=DMARC1; p=reject; rua=...' -> {'v': 'DMARC1', 'p': 'reject', 'rua': '...'}"""
    tags = {}
    for part in record.split(";"):
        name, _, value = part.partition("=")
        if value:
            tags[name.strip().lower()] = value.strip()
    return tags


def check_dmarc(dmarc_records: list[str]) -> list[dict]:
    dmarc = [record for record in dmarc_records if record.lower().startswith("v=dmarc1")]
    if not dmarc:
        return [make_finding("dns.dmarc_missing")]
    policy = parse_tags(dmarc[0]).get("p", "").lower()
    if len(dmarc) > 1 or policy not in DMARC_POLICIES:
        return [make_finding("dns.dmarc_invalid", record=dmarc[0])]
    if policy == "none":
        return [make_finding("dns.dmarc_policy_none", record=dmarc[0])]
    return []


def analyze(a: list[str], mx: list[str], txt: list[str], dmarc: list[str]) -> list[dict]:
    findings = []
    if not a:
        findings.append(make_finding("dns.no_a_record"))
    if not mx:
        findings.append(make_finding("dns.no_mx_record"))
    return findings + check_spf(txt) + check_dmarc(dmarc)


@router.post("/dns-check")
def dns_check(body: DnsCheckRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    guard.check_rate_limit(user)
    domain = body.domain
    try:
        a, mx, txt = lookup(domain, "A"), lookup(domain, "MX"), lookup(domain, "TXT")
        dmarc = lookup(f"_dmarc.{domain}", "TXT")
    except dns.exception.DNSException:
        raise HTTPException(502, "The DNS lookup failed or timed out. Please try again.") from None
    if not (a or mx or txt):
        raise HTTPException(404, f"No DNS records found for {domain}. Check the spelling.")

    spf = next((r for r in txt if r.lower().startswith("v=spf1")), None)
    summary = {"a": a, "mx": mx, "txt": txt, "spf": spf, "dmarc": dmarc[0] if dmarc else None}
    guard.log_activity(db, user, "dns_check", domain)
    return save_scan(db, user, "dns_check", domain, summary, analyze(a, mx, txt, dmarc))
