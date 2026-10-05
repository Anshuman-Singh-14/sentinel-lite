"""All tools that run on the server. app.py registers each tool's router.

Each tool module has a LABEL (shown in history and reports) and a `router`.
"""

from backend.tools import dns_check, log_analyzer, port_scan, web_check

TOOLS = {
    "dns_check": dns_check,
    "port_scan": port_scan,
    "web_check": web_check,
    "log_analyzer": log_analyzer,
}
