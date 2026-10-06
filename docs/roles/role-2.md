# Role 2: Network Security Tools

My part is the DNS & email check, the port scanner and the website check
(`backend/tools/dns_check.py`, `port_scan.py`, `web_check.py`) and their tests.

## Port scan: open or closed?

The scanner tries a normal TCP connection (full handshake) to each port. If it connects, the port
is **open**. If it is refused or there is no answer within 2 seconds, it counts as **closed**.
No data is sent. Limits: 100 ports per scan, 50 connections at a time, approved targets only.

## SPF and DMARC

Anyone can send an email that claims to be from your domain (spoofing). SPF and DMARC are DNS
records that stop this.

- **SPF** lists which servers may send mail for the domain. It should end in `-all` or `~all`;
  `+all` lets any server send.
- **DMARC** tells receivers what to do with mail that fails: `none`, `quarantine` or `reject`.
  `none` only monitors, so we flag it.

## The 6 security headers

- **HSTS:** always use HTTPS, so traffic can't be downgraded to HTTP.
- **Content-Security-Policy:** limits where scripts load from, which helps stop XSS.
- **X-Frame-Options:** stops the page being framed by other sites (clickjacking).
- **X-Content-Type-Options:** stops the browser guessing file types.
- **Referrer-Policy:** stops full URLs leaking to other sites.
- **Permissions-Policy:** turns off unused features like the camera and location.

## Tests

The tests use sample data, so they don't need the internet. Run them with `python -m pytest`.
