import re
import pandas as pd


CVE_PATTERN = re.compile(
    r"\bCVE[-_\s:]?(\d{4})[-_\s:]?(\d{4,})\b",
    re.IGNORECASE
)


def normalize_cve(value):
    """
    Extract and normalize CVE IDs from a field.

    Example:
        cve-2023-1234
        CVE:2023:1234
        cve_2023_1234

    becomes:
        CVE-2023-1234
    """

    if pd.isna(value):
        return "N/A"

    text = str(value).strip()

    if not text:
        return "N/A"

    matches = CVE_PATTERN.findall(text)

    if not matches:
        return "N/A"

    cves = []

    for year, number in matches:
        cve = f"CVE-{year}-{number}"

        if cve not in cves:
            cves.append(cve)

    return "; ".join(cves)


def extract_cves(value):
    """
    Return CVEs as a Python list.
    """

    if pd.isna(value):
        return []

    text = str(value)

    matches = CVE_PATTERN.findall(text)

    cves = []

    for year, number in matches:
        cve = f"CVE-{year}-{number}"

        if cve not in cves:
            cves.append(cve)

    return cves