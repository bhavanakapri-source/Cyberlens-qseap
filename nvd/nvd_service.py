
"""Optional NVD/vendor enrichment for CyberLens.

Traditional Qualys and Nessus/Plugins retrieval remains primary.
NVD adds supplemental evidence only. External lookup failures must
never break the original dataset-grounded answer.
"""

from __future__ import annotations

import re
from typing import Any

try:
    from nvd.nvd_client import (
        fetch_cve as client_fetch_cve,
        search_cves,
        search_vendor_updates,
    )
except ImportError:
    try:
        from nvd_client import (
            fetch_cve as client_fetch_cve,
            search_cves,
            search_vendor_updates,
        )
    except ImportError:
        client_fetch_cve = None
        search_cves = None
        search_vendor_updates = None


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

FIELD_ALIASES = {
    "vendor": (
        "vendor", "VENDOR", "ORG_VENDOR", "vendor_name",
        "true_vendor", "SOFTWARE_VENDOR", "software_vendor",
    ),
    "product": (
        "product", "PRODUCT", "ORG_PRODUCT", "product_name",
        "true_product", "SOFTWARE_PRODUCT", "software_product",
    ),
    "title": (
        "title", "TITLE", "VULNERABILITY_TITLE",
        "vulnerability_title", "name",
    ),
    "diagnosis": (
        "diagnosis", "DIAGNOSIS", "description", "DESCRIPTION",
    ),
    "solution": (
        "solution", "SOLUTION", "remediation", "REMEDIATION", "fix", "FIX",
    ),
    "qid": ("qid", "QID"),
    "plugin_id": ("plugin_id", "PLUGIN_ID", "script_id", "SCRIPT_ID"),
    "affected_version": (
        "affected_version", "AFFECTED_VERSION",
        "version", "VERSION", "software_version", "SOFTWARE_VERSION",
    ),
    "cve": ("cve", "CVE", "CVE_LIST", "cve_id", "CVE_ID"),
}


def fetch_cve(cve_id: str) -> dict | None:
    """Fetch one CVE using the NVD client's exact-CVE lookup."""

    if not cve_id or client_fetch_cve is None:
        return None

    requested_id = cve_id.strip().upper()

    try:
        response = client_fetch_cve(requested_id)
    except Exception:
        return None

    if not isinstance(response, dict):
        return None

    vulnerabilities = response.get("vulnerabilities")

    if isinstance(vulnerabilities, list) and vulnerabilities:
        item = vulnerabilities[0]

        if isinstance(item, dict):
            cve = item.get("cve", item)

            if isinstance(cve, dict):
                response_id = str(cve.get("id", "")).strip().upper()
                return cve if response_id == requested_id else None

    cve = response.get("cve")

    if isinstance(cve, dict):
        response_id = str(cve.get("id", "")).strip().upper()
        return cve if response_id == requested_id else None

    response_id = str(response.get("id", "")).strip().upper()

    if response_id == requested_id:
        return response

    return None


def _field(payload: dict, aliases: tuple[str, ...]) -> str:
    """Read a field using known dataset column aliases."""

    if not isinstance(payload, dict):
        return ""

    for key in aliases:
        value = payload.get(key)

        if value is None:
            continue

        if isinstance(value, (list, tuple, set)):
            value = ", ".join(str(item) for item in value if item)

        value = str(value).strip()

        if value:
            return value

    return ""


def _normalise_results(results: Any) -> list[dict]:
    """Normalize common vector-store result formats to payloads."""

    if isinstance(results, dict):
        results = [results]

    if not isinstance(results, (list, tuple)):
        return []

    payloads = []

    for result in results:
        if isinstance(result, dict):
            payload = result.get("payload", result)
        else:
            payload = getattr(result, "payload", None)

        if isinstance(payload, dict):
            payloads.append(payload)

    return payloads


def _first_result_field(results: Any, field_name: str) -> str:
    """Return the first non-empty matching field."""

    aliases = FIELD_ALIASES.get(field_name, (field_name,))

    for payload in _normalise_results(results):
        value = _field(payload, aliases)

        if value:
            return value

    return ""


def _results_to_text(results: Any) -> str:
    """Convert retrieved results to text without changing their content."""

    if isinstance(results, str):
        return results

    if isinstance(results, dict):
        return repr(results)

    if isinstance(results, (list, tuple, set)):
        return "\n\n".join(_results_to_text(item) for item in results)

    payload = getattr(results, "payload", None)

    if isinstance(payload, dict):
        return repr(payload)

    page_content = getattr(results, "page_content", None)

    if isinstance(page_content, str):
        return page_content

    return str(results)


def _extract_cves_from_payload(
    results: Any,
    user_query: str = "",
) -> list[str]:
    """Extract CVEs, prioritizing identifiers explicitly requested."""

    query_cves = list(dict.fromkeys(
        match.upper()
        for match in CVE_PATTERN.findall(str(user_query))
    ))

    found: list[str] = query_cves.copy()

    def add_from(value: Any) -> None:
        if value is None:
            return

        if isinstance(value, dict):
            for key, nested_value in value.items():
                add_from(key)
                add_from(nested_value)
            return

        if isinstance(value, (list, tuple, set)):
            for nested_value in value:
                add_from(nested_value)
            return

        for match in CVE_PATTERN.findall(str(value)):
            cve_id = match.upper()

            if cve_id not in found:
                found.append(cve_id)

    for payload in _normalise_results(results):
        for key in FIELD_ALIASES["cve"]:
            add_from(payload.get(key))

    add_from(results)
    add_from(_results_to_text(results))

    return found


def _english_description(cve: dict) -> str:
    """Extract the English CVE description."""

    descriptions = cve.get("descriptions", [])

    if not isinstance(descriptions, list):
        return ""

    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value", "")).strip()

    if descriptions and isinstance(descriptions[0], dict):
        return str(descriptions[0].get("value", "")).strip()

    return ""


def _cpe_product_text(cve: dict) -> str:
    """Extract NVD CPE entries and explicit version boundaries."""

    collected: list[str] = []

    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return

        matches = node.get("cpeMatch", [])

        if isinstance(matches, list):
            for match in matches:
                if not isinstance(match, dict):
                    continue

                criteria = match.get("criteria")

                if not criteria:
                    continue

                details = [f"CPE: {criteria}"]

                version_fields = (
                    ("versionStartIncluding", "version start inclusive"),
                    ("versionStartExcluding", "version start exclusive"),
                    ("versionEndIncluding", "version end inclusive"),
                    ("versionEndExcluding", "version end exclusive"),
                )

                for key, label in version_fields:
                    if match.get(key) is not None:
                        details.append(f"{label}: {match[key]}")

                details.append(
                    f"vulnerable: {match.get('vulnerable', 'Unknown')}"
                )

                collected.append("; ".join(details))

        for key in ("nodes", "children"):
            children = node.get(key, [])

            if isinstance(children, list):
                for child in children:
                    walk(child)

    configurations = cve.get("configurations", [])

    if isinstance(configurations, list):
        for configuration in configurations:
            walk(configuration)

    return "\n".join(dict.fromkeys(collected))


def _query_keywords(user_query: str, results: Any) -> str:
    """Build fallback NVD keyword-search terms."""

    parts = [str(user_query or "").strip()]

    for field_name in ("vendor", "product", "title", "diagnosis"):
        value = _first_result_field(results, field_name)

        if value:
            parts.append(value)

    if len(parts) == 1:
        parts.append(_results_to_text(results)[:1500])

    return " ".join(part for part in parts if part).strip()


def _search_relevant_records(keywords: str) -> list[dict]:
    """Perform a fallback NVD keyword search."""

    if search_cves is None or not keywords:
        return []

    try:
        response = search_cves(keyword=keywords)
    except TypeError:
        try:
            response = search_cves(keywords)
        except Exception:
            return []
    except Exception:
        return []

    if isinstance(response, list):
        return [item for item in response if isinstance(item, dict)]

    if not isinstance(response, dict):
        return []

    records = response.get("vulnerabilities", [])

    if not isinstance(records, list):
        return []

    return [item for item in records if isinstance(item, dict)]


def _format_record(record: dict) -> str:
    """Format an NVD CVE record as readable supplemental evidence."""

    if not isinstance(record, dict):
        return ""

    cve = record.get("cve", record)

    if not isinstance(cve, dict):
        return ""

    cve_id = cve.get("id", "Unknown CVE")

    lines = [
        f"CVE: {cve_id}",
        "Description: "
        + (
            _english_description(cve)
            or "No English description available."
        ),
    ]

    metrics = cve.get("metrics", {})

    if isinstance(metrics, dict):
        metric_names = (
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        )

        for metric_name in metric_names:
            entries = metrics.get(metric_name, [])

            if (
                not isinstance(entries, list)
                or not entries
                or not isinstance(entries[0], dict)
            ):
                continue

            data = entries[0].get("cvssData", {})

            if isinstance(data, dict):
                lines.append(f"CVSS source metric: {metric_name}")

                if data.get("baseScore") is not None:
                    lines.append(f"CVSS base score: {data['baseScore']}")

                severity = (
                    data.get("baseSeverity")
                    or entries[0].get("baseSeverity")
                )

                if severity:
                    lines.append(f"CVSS severity: {severity}")

            break

    product_text = _cpe_product_text(cve)

    lines.extend([
        "NVD affected-version evidence:",
        product_text or "No applicable CPE version ranges were extracted.",
    ])

    references = cve.get("references", [])

    if isinstance(references, list):
        urls = [
            item["url"]
            for item in references[:8]
            if isinstance(item, dict) and item.get("url")
        ]

        if urls:
            lines.append("NVD references:")
            lines.extend(urls)

    lines.append(
        "NVD version boundaries do not, by themselves, establish a fixed "
        "version or latest supported release. Confirm the fix with "
        "applicable vendor documentation."
    )

    return "\n".join(lines)


def _vendor_update_guidance(
    vendor: str,
    product: str,
    cve_id: str | None = None,
    affected_version: str | None = None,
) -> str:
    """Append optional vendor-search evidence without inventing fixes."""

    if search_vendor_updates is None:
        return (
            "VENDOR VERIFICATION: Vendor search is unavailable. "
            "The fixed version and remediation command have not been "
            "independently verified."
        )

    if not vendor or not product:
        return (
            "VENDOR VERIFICATION: Vendor and product could not both be "
            "identified from the retrieved record. No product-specific "
            "vendor search was performed."
        )

    try:
        response = search_vendor_updates(
            vendor=vendor,
            product=product,
            cve_id=cve_id,
            affected_version=affected_version,
        )

        if not isinstance(response, dict):
            return (
                "VENDOR VERIFICATION: Unexpected search response. "
                "The remediation command remains unverified."
            )

        status = response.get("status", "unknown")
        message = response.get("message", "")
        results = response.get("results", [])

        lines = [
            "VENDOR REMEDIATION VERIFICATION",
            f"Vendor: {vendor}",
            f"Product: {product}",
            f"CVE: {cve_id or 'Not identified'}",
            f"Search status: {status}",
        ]

        if message:
            lines.append(f"Search result: {message}")

        if status != "vendor_sources_found" or not results:
            lines.extend([
                "No usable vendor evidence was established.",
                "Do not invent a fixed version or product-specific command.",
                "Treat dataset remediation as recorded dataset evidence, "
                "not independently verified vendor guidance.",
            ])

            return "\n".join(lines)

        lines.append(
            "Vendor search results are evidence candidates. Confirm that "
            "each source applies to the exact product, platform, CVE, "
            "and release before relying on its remediation."
        )

        for item in results[:6]:
            if not isinstance(item, dict):
                continue

            lines.extend([
                f"Title: {item.get('title', 'Not provided')}",
                f"URL: {item.get('url', 'Not provided')}",
                f"Content: {item.get('content', 'Not provided')}",
                "",
            ])

        lines.append(
            "A vendor-domain match alone does not prove the latest "
            "supported release. Recommend an exact command only when "
            "applicable source content supports it."
        )

        return "\n".join(lines)

    except Exception:
        return (
            "VENDOR VERIFICATION: Vendor-source lookup failed. "
            "The original dataset evidence is preserved. The fixed "
            "version and remediation command remain unverified."
        )


def _wrap(evidence: str) -> str:
    """Keep the wrapper markers expected by existing tests."""

    return (
        "\n\n========== OPTIONAL NVD VERSION EVIDENCE ==========\n"
        f"{evidence}\n"
        "========== END NVD EVIDENCE ==========\n"
    )


def enrich_results_with_nvd(
    results: Any,
    user_query: str = "",
) -> str:
    """Append optional NVD/vendor evidence to the original context.

    Original Qualys and Nessus/Plugins evidence is preserved.
    Supplemental lookup failures are non-fatal.
    """

    original_text = _results_to_text(results)
    evidence_sections: list[str] = []
    query = str(user_query or "")

    try:
        # IMPORTANT: CVEs explicitly typed by the user are checked first,
        # even if the retrieved Qdrant payload contains no CVE field.
        query_cves = list(dict.fromkeys(
            match.upper()
            for match in CVE_PATTERN.findall(query)
        ))

        # Preserve existing payload-based CVE extraction and deduplication.
        cve_ids = _extract_cves_from_payload(results, query)

        # Explicit query CVEs must remain first.
        cve_ids = query_cves + [
            cve for cve in cve_ids if cve not in query_cves
        ]

        if cve_ids:
            evidence_sections.append("NVD API lookup results:")

            if client_fetch_cve is None:
                evidence_sections.append(
                    "NVD API lookup is unavailable. Original dataset "
                    "evidence remains available."
                )
            else:
                for cve_id in cve_ids[:5]:
                    record = fetch_cve(cve_id)

                    if not record:
                        evidence_sections.append(
                            f"{cve_id}: The NVD API could not retrieve a record "
                            "for this identifier. This does not prove that "
                            "the CVE does not exist."
                        )
                        continue

                    formatted = _format_record(record)

                    if formatted:
                        evidence_sections.append(formatted)
                    else:
                        evidence_sections.append(
                            f"{cve_id}: The NVD response contained no usable "
                            "vulnerability details."
                        )

        else:
            # Existing natural-language / product keyword search stays intact.
            keywords = _query_keywords(query, results)
            records = _search_relevant_records(keywords)
            relevant: list[str] = []

            for record in records:
                formatted = _format_record(record)

                if formatted:
                    relevant.append(formatted)

            evidence_sections.append("NVD API keyword search results:")

            if relevant:
                evidence_sections.extend(relevant[:5])
            else:
                evidence_sections.append(
                    "No relevant NVD record was found for the supplied "
                    "product or natural-language query. NVD version "
                    "evidence is unavailable."
                )

        vendor = _first_result_field(results, "vendor")
        product = _first_result_field(results, "product")
        cve_id = cve_ids[0] if cve_ids else None
        affected_version = _first_result_field(
            results,
            "affected_version",
        )

        evidence_sections.append(
            _vendor_update_guidance(
                vendor=vendor,
                product=product,
                cve_id=cve_id,
                affected_version=affected_version or None,
            )
        )

    except Exception:
        # Never block the original retrieval/LLM answer.
        evidence_sections.append(
            "NVD enrichment encountered an error. "
            "The original retrieved evidence is preserved. "
            "Additional NVD details are unavailable."
        )

    evidence = "\n\n".join(
        section for section in evidence_sections if section
    )

    if not evidence:
        evidence = "NVD enrichment did not produce additional evidence."

    return original_text + _wrap(evidence)
