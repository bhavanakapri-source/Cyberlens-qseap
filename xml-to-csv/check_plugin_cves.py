import csv
import glob
import re
import sys
from collections import Counter


# ============================================================
# ALLOW VERY LARGE CSV FIELDS
# ============================================================

csv.field_size_limit(sys.maxsize)


# ============================================================
# CONFIGURATION
# ============================================================

FILES = sorted(glob.glob("output/plugins_part_*.csv"))

CVE_PATTERN = re.compile(
    r"CVE-\d{4}-\d{4,}",
    re.IGNORECASE
)


# ============================================================
# COUNTERS
# ============================================================

total_records = 0
records_with_cve = 0
records_without_cve = 0

unique_cves = set()
cve_frequency = Counter()

multiple_cve_records = 0

files_checked = 0


# ============================================================
# PROCESS FILES
# ============================================================

for file_path in FILES:

    print(f"Checking: {file_path}")

    files_checked += 1

    with open(
        file_path,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        # ----------------------------------------------------
        # Check CVE column
        # ----------------------------------------------------

        if "cves" not in reader.fieldnames:

            print("  WARNING: 'cves' column not found!")
            print("  Columns found:", reader.fieldnames)

            continue

        # ----------------------------------------------------
        # Process records one by one
        # ----------------------------------------------------

        for row in reader:

            total_records += 1

            cve_value = (row.get("cves") or "").strip()

            # Extract CVE IDs
            found_cves = set(
                match.upper()
                for match in CVE_PATTERN.findall(cve_value)
            )

            # ------------------------------------------------
            # Record contains CVE
            # ------------------------------------------------

            if found_cves:

                records_with_cve += 1

                if len(found_cves) > 1:
                    multiple_cve_records += 1

                for cve in found_cves:

                    unique_cves.add(cve)

                    cve_frequency[cve] += 1

            # ------------------------------------------------
            # Record does NOT contain CVE
            # ------------------------------------------------

            else:

                records_without_cve += 1


# ============================================================
# FINAL REPORT
# ============================================================

print("\n" + "=" * 70)
print("PLUGIN CVE ANALYSIS")
print("=" * 70)

print(f"Files checked:                  {files_checked:,}")
print(f"Total plugin records:           {total_records:,}")
print(f"Records WITH CVE:               {records_with_cve:,}")
print(f"Records WITHOUT CVE:            {records_without_cve:,}")
print(f"Records with MULTIPLE CVEs:     {multiple_cve_records:,}")
print(f"Unique CVEs:                    {len(unique_cves):,}")

if total_records > 0:

    percentage = (
        records_with_cve / total_records
    ) * 100

    print(
        f"Records containing CVE:         "
        f"{percentage:.2f}%"
    )


# ============================================================
# TOP CVEs
# ============================================================

print("\n" + "=" * 70)
print("TOP 20 MOST FREQUENT CVEs")
print("=" * 70)

for cve, count in cve_frequency.most_common(20):

    print(
        f"{cve:20} → "
        f"{count:,} plugin records"
    )


print("\nAnalysis complete.")