
def _walk_configuration(node):
    """Recursively yield CPE match entries from NVD configurations."""
    if not isinstance(node, dict):
        return

    for match in node.get("cpeMatch", []):
        if isinstance(match, dict):
            yield match

    for key in ("children", "nodes"):
        for child in node.get(key, []):
            yield from _walk_configuration(child)


def extract_version_info(cve_record: dict | None) -> dict:
    """
    Extract affected version ranges, dates, and official references
    from an NVD CVE record.

    Version boundaries are not automatically the latest release.
    """
    empty_result = {
        "cve": None,
        "description": None,
        "published": None,
        "last_modified": None,
        "version_ranges": [],
        "references": [],
        "status": "no_version_information",
    }

    if not isinstance(cve_record, dict):
        return empty_result

    descriptions = cve_record.get("descriptions", [])

    description = next(
        (
            item.get("value")
            for item in descriptions
            if item.get("lang") == "en" and item.get("value")
        ),
        None,
    )

    version_ranges = []

    for configuration in cve_record.get("configurations", []):
        if not isinstance(configuration, dict):
            continue

        for node in configuration.get("nodes", []):
            for match in _walk_configuration(node):
                version_ranges.append({
                    "criteria": match.get("criteria"),
                    "vulnerable": match.get("vulnerable"),
                    "version_start_including": match.get(
                        "versionStartIncluding"
                    ),
                    "version_start_excluding": match.get(
                        "versionStartExcluding"
                    ),
                    "version_end_including": match.get(
                        "versionEndIncluding"
                    ),
                    "version_end_excluding": match.get(
                        "versionEndExcluding"
                    ),
                    "match_criteria_id": match.get("matchCriteriaId"),
                })

    references = []

    for reference in cve_record.get("references", []):
        if not isinstance(reference, dict):
            continue

        url = reference.get("url")
        if not url:
            continue

        tags = reference.get("tags", [])

        references.append({
            "url": url,
            "tags": tags if isinstance(tags, list) else [],
        })

    return {
        "cve": cve_record.get("id"),
        "description": description,
        "published": cve_record.get("published"),
        "last_modified": cve_record.get("lastModified"),
        "version_ranges": version_ranges,
        "references": references,
        "status": (
            "version_ranges_found"
            if version_ranges
            else "no_version_information"
        ),
    }
