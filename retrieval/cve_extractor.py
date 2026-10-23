import re


CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE
)

QID_PATTERN = re.compile(
    r"\b(?:QID|QID\s*NUMBER)\s*[:#-]?\s*(\d+)\b",
    re.IGNORECASE
)

PLUGIN_ID_PATTERN = re.compile(
    r"\b(?:PLUGIN\s*ID|PLUGIN|SCRIPT\s*ID|SCRIPT)\s*[:#-]?\s*(\d+)\b",
    re.IGNORECASE
)

BID_PATTERN = re.compile(
    r"\b(?:BID|BUGTRAQ)\s*[:#-]?\s*(\d+)\b",
    re.IGNORECASE
)


SECURITY_KEYWORDS = {
    "fix",
    "solution",
    "patch",
    "remediation",
    "vulnerability",
    "vulnerabilities",
    "exploit",
    "exploitable",
    "security",
    "update",
    "affected",
    "severity",
    "critical",
    "high",
    "medium",
    "low",
    "diagnosis",
    "risk",
}


def extract_cves(query: str) -> list[str]:
    matches = CVE_PATTERN.findall(query)

    return sorted(
        set(cve.upper() for cve in matches)
    )


def extract_qids(query: str) -> list[int]:
    matches = QID_PATTERN.findall(query)

    return sorted(
        set(int(qid) for qid in matches)
    )


def extract_plugin_ids(query: str) -> list[int]:
    matches = PLUGIN_ID_PATTERN.findall(query)

    return sorted(
        set(int(plugin_id) for plugin_id in matches)
    )


def extract_bids(query: str) -> list[int]:
    matches = BID_PATTERN.findall(query)

    return sorted(
        set(int(bid) for bid in matches)
    )


def extract_keywords(query: str) -> list[str]:
    query_lower = query.lower()

    found = []

    for keyword in SECURITY_KEYWORDS:
        if keyword in query_lower:
            found.append(keyword)

    return sorted(found)


def extract_entities(query: str) -> dict:
    """
    Extract structured identifiers and security-related information
    from the user's query.

    Identifiers are extracted separately because QID, Plugin ID,
    BID, and CVE belong to different identifier namespaces.
    """

    return {
        "cves": extract_cves(query),
        "qids": extract_qids(query),
        "plugin_ids": extract_plugin_ids(query),
        "bids": extract_bids(query),
        "keywords": extract_keywords(query),
        "query_lower": query.lower(),
    }