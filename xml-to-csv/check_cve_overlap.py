import csv
import glob
import re
import sys

# Allow very large CSV fields
csv.field_size_limit(sys.maxsize)

# Match CVE IDs
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

PLUGIN_FILES = "output/plugins_part_*.csv"
QUALYS_FILES = "output/qualys_part_*.csv"


def extract_cves(text):
    """Extract CVE IDs from text."""
    if not text:
        return set()

    return {
        cve.upper()
        for cve in CVE_PATTERN.findall(str(text))
    }


# ============================================================
# 1. COLLECT PLUGIN CVEs
# ============================================================

print("=" * 70)
print("COLLECTING PLUGIN CVEs")
print("=" * 70)

plugin_cves = set()

plugin_files = sorted(glob.glob(PLUGIN_FILES))

for file in plugin_files:
    print(f"Reading {file}...")

    with open(file, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            cves = extract_cves(row.get("cves", ""))
            plugin_cves.update(cves)

print()
print(f"Unique Plugin CVEs : {len(plugin_cves):,}")


# ============================================================
# 2. COLLECT QUALYS CVEs
# ============================================================

print()
print("=" * 70)
print("COLLECTING QUALYS CVEs")
print("=" * 70)

qualys_cves = set()

qualys_files = sorted(glob.glob(QUALYS_FILES))

for file in qualys_files:
    print(f"Reading {file}...")

    with open(file, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:

            # Same fields used in the previous Qualys analysis
            fields = [
                row.get("TITLE", ""),
                row.get("SOFTWARE_PRODUCT", ""),
                row.get("SOFTWARE_VENDOR", ""),
                row.get("DIAGNOSIS", ""),
            ]

            for field in fields:
                qualys_cves.update(extract_cves(field))

print()
print(f"Unique Qualys CVEs  : {len(qualys_cves):,}")


# ============================================================
# 3. CALCULATE OVERLAP
# ============================================================

common_cves = plugin_cves & qualys_cves
plugin_only = plugin_cves - qualys_cves
qualys_only = qualys_cves - plugin_cves


# ============================================================
# 4. CALCULATE PERCENTAGES
# ============================================================

plugin_overlap_percentage = (
    len(common_cves) / len(plugin_cves) * 100
    if plugin_cves
    else 0
)

qualys_overlap_percentage = (
    len(common_cves) / len(qualys_cves) * 100
    if qualys_cves
    else 0
)


# ============================================================
# 5. FINAL REPORT
# ============================================================

print()
print("=" * 70)
print("CVE OVERLAP ANALYSIS")
print("=" * 70)

print(f"Plugin unique CVEs       : {len(plugin_cves):,}")
print(f"Qualys unique CVEs       : {len(qualys_cves):,}")
print("-" * 70)
print(f"COMMON CVEs               : {len(common_cves):,}")
print(f"Only in Plugins           : {len(plugin_only):,}")
print(f"Only in Qualys            : {len(qualys_only):,}")
print("-" * 70)

print(
    f"Plugin CVEs also in Qualys: "
    f"{plugin_overlap_percentage:.2f}%"
)

print(
    f"Qualys CVEs also in Plugins: "
    f"{qualys_overlap_percentage:.2f}%"
)

print("=" * 70)


# ============================================================
# 6. SHOW SAMPLE COMMON CVEs
# ============================================================

print()
print("SAMPLE COMMON CVEs")
print("-" * 70)

for cve in sorted(common_cves)[:50]:
    print(cve)

print()
print("Analysis complete.")