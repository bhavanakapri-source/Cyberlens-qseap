
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TAVILY_API_URL = "https://api.tavily.com/search"

CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE,
)

# Known official vendor domains. Add more when your supported vendors
# require a domain that does not contain the vendor's name.
OFFICIAL_VENDOR_DOMAINS = {
    "red hat": ["redhat.com", "access.redhat.com"],
    "redhat": ["redhat.com", "access.redhat.com"],
    "microsoft": [
        "microsoft.com",
        "msrc.microsoft.com",
        "support.microsoft.com",
        "learn.microsoft.com",
    ],
    "tembria": ["tembria.com"],
    "adobe": ["adobe.com"],
    "cisco": ["cisco.com"],
    "oracle": ["oracle.com"],
    "ibm": ["ibm.com"],
    "google": ["google.com"],
    "apache": ["apache.org"],
    "mozilla": ["mozilla.org"],
    "fortinet": ["fortinet.com"],
    "palo alto networks": ["paloaltonetworks.com"],
    "vmware": ["broadcom.com", "vmware.com"],
    "broadcom": ["broadcom.com"],
}


def _get_json(params):
    """Call the official NVD API with a bounded timeout."""
    headers = {
        "User-Agent": "CyberLens-Vulnerability-Assistant/1.0",
        "Accept": "application/json",
    }

    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    url = f"{NVD_API_URL}?{urlencode(params)}"
    request = Request(url, headers=headers, method="GET")

    try:
        with urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))

        return data if isinstance(data, dict) else None

    except (
        HTTPError,
        URLError,
        TimeoutError,
        OSError,
        ValueError,
    ):
        return None


def fetch_cve(cve_id):
    """Fetch one CVE by exact identifier."""
    if not isinstance(cve_id, str):
        return None

    cve_id = cve_id.strip().upper()

    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id):
        return None

    data = _get_json({"cveId": cve_id})
    if data is None:
        return None

    for item in data.get("vulnerabilities", []):
        record = item.get("cve", {})
        if record.get("id", "").upper() == cve_id:
            return record

    return None


def search_cves(keyword, limit=5):
    """
    Search NVD by product, vendor, vulnerability title, or keywords.

    Returns:
        list: search results, possibly empty.
        None: request failed or NVD was unavailable.
    """
    if not isinstance(keyword, str):
        return None

    keyword = " ".join(keyword.split()).strip()

    if len(keyword) < 3:
        return []

    limit = max(1, min(int(limit), 5))

    data = _get_json({
        "keywordSearch": keyword[:200],
        "resultsPerPage": limit,
    })

    if data is None:
        return None

    records = []

    for item in data.get("vulnerabilities", []):
        record = item.get("cve")

        if isinstance(record, dict) and record.get("id"):
            records.append(record)

    return records


def _allowed_vendor_domains(vendor, references=None):
    """Return domains that can reasonably be treated as vendor sources."""
    vendor_key = (vendor or "").strip().lower()
    domains = set(OFFICIAL_VENDOR_DOMAINS.get(vendor_key, []))

    # NVD references may contain a vendor's actual advisory domain.
    # Only accept references whose hostname contains the vendor name.
    if vendor_key and references:
        vendor_tokens = re.findall(r"[a-z0-9]+", vendor_key)

        for reference in references:
            url = reference.get("url", "")
            match = re.match(r"https?://([^/:?#]+)", url, re.I)

            if not match:
                continue

            host = match.group(1).lower()
            host_without_www = host.removeprefix("www.")

            if any(
                token in host_without_www
                for token in vendor_tokens
                if len(token) >= 4
            ):
                domains.add(host_without_www)

    return sorted(domains)


def search_vendor_updates(
    vendor,
    product,
    cve_id=None,
    affected_version=None,
    references=None,
):
    """
    Search for vendor release notes, security advisories, and fixed
    versions. Results are evidence candidates, not automatic proof
    that a release is the latest supported version.

    Requires TAVILY_API_KEY. Only results from recognized vendor
    domains or vendor-matching domains are returned.
    """
    api_key = os.getenv("TAVILY_API_KEY")

    if not api_key:
        return {
            "status": "vendor_search_not_configured",
            "message": (
                "TAVILY_API_KEY is not configured. Current vendor "
                "release verification was not performed."
            ),
            "results": [],
        }

    if not vendor or not product:
        return {
            "status": "insufficient_product_information",
            "message": (
                "Vendor and product are required for vendor-source "
                "verification."
            ),
            "results": [],
        }

    terms = [
        str(vendor),
        str(product),
        "official security advisory fixed version latest supported release",
    ]

    if cve_id:
        terms.append(str(cve_id))

    if affected_version:
        terms.append(f"affected version {affected_version}")

    query = " ".join(terms)
    allowed_domains = _allowed_vendor_domains(vendor, references)

    body = {
        "api_key": api_key,
        "query": query,
        "search_depth": "advanced",
        "max_results": 8,
        "include_answer": False,
    }

    if allowed_domains:
        body["include_domains"] = allowed_domains

    request = Request(
        TAVILY_API_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CyberLens-Vulnerability-Assistant/1.0",
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))

    except (
        HTTPError,
        URLError,
        TimeoutError,
        OSError,
        ValueError,
    ):
        return {
            "status": "vendor_search_failed",
            "message": (
                "The live vendor-source search failed. The latest "
                "supported release could not be verified."
            ),
            "results": [],
        }

    verified_candidates = []

    for item in data.get("results", []):
        url = item.get("url", "")
        match = re.match(r"https?://([^/:?#]+)", url, re.I)

        if not match:
            continue

        host = match.group(1).lower().removeprefix("www.")

        # Do not treat arbitrary search results as official vendor
        # evidence. When no recognized domain exists, require the
        # hostname to match a meaningful vendor token.
        if allowed_domains:
            is_vendor_domain = any(
                host == domain or host.endswith("." + domain)
                for domain in allowed_domains
            )
        else:
            vendor_tokens = [
                token for token in re.findall(
                    r"[a-z0-9]+", str(vendor).lower()
                )
                if len(token) >= 4
            ]
            is_vendor_domain = any(
                token in host for token in vendor_tokens
            )

        if not is_vendor_domain:
            continue

        verified_candidates.append({
            "title": str(item.get("title", ""))[:300],
            "url": url,
            "domain": host,
            "content": str(
                item.get("content", item.get("snippet", ""))
            )[:1800],
            "source_type": "vendor_domain_candidate",
        })

    return {
        "status": (
            "vendor_sources_found"
            if verified_candidates
            else "no_verified_vendor_sources"
        ),
        "message": (
            "Vendor-domain candidates found. Check the source content "
            "to establish the fixed version and current support status."
            if verified_candidates
            else
            "No suitable vendor-domain results were found. The latest "
            "supported release remains unverified."
        ),
        "results": verified_candidates[:6],
    }
