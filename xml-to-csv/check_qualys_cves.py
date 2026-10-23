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

FILES = sorted(glob.glob("output/qualys_part_*.csv"))

# Standard CVE format:
# CVE-2024-12345
# CVE-2023-1234
CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE
)


# ============================================================
# COLUMNS WE WANT TO CHECK
# ============================================================

COLUMNS_TO_CHECK = [
    "QID",
    "TITLE",
    "SOFTWARE_PRODUCT",
    "SOFTWARE_VENDOR",
    "DIAGNOSIS",
]


# ============================================================
# COUNTERS
# ============================================================

total_records = 0

records_with_cve = 0
records_without_cve = 0

unique_cves = set()

cve_frequency = Counter()

# Number of records containing CVEs in each column
column_record_counts = Counter()

# Total CVE occurrences found in each column
column_cve_counts = Counter()

# Keep track of CVEs by column
cves_by_column = {
    column: set()
    for column in COLUMNS_TO_CHECK
}

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
        # Check columns
        # ----------------------------------------------------

        if reader.fieldnames is None:

            print("  WARNING: No columns found!")

            continue

        # Remove BOM/whitespace just in case
        fieldnames = [
            column.strip()
            for column in reader.fieldnames
        ]

        available_columns = [
            column
            for column in COLUMNS_TO_CHECK
            if column in fieldnames
        ]

        print(
            f"  Columns being checked: "
            f"{', '.join(available_columns)}"
        )

        # ----------------------------------------------------
        # Process records
        # ----------------------------------------------------

        for row in reader:

            total_records += 1

            record_has_cve = False

            # ------------------------------------------------
            # Check each relevant column
            # ------------------------------------------------

            for column in available_columns:

                value = (row.get(column) or "").strip()

                if not value:
                    continue

                found_cves = set(
                    match.upper()
                    for match in CVE_PATTERN.findall(value)
                )

                if found_cves:

                    record_has_cve = True

                    column_record_counts[column] += 1

                    column_cve_counts[column] += len(found_cves)

                    for cve in found_cves:

                        unique_cves.add(cve)

                        cve_frequency[cve] += 1

                        cves_by_column[column].add(cve)

            # ------------------------------------------------
            # Record-level CVE count
            # ------------------------------------------------

            if record_has_cve:

                records_with_cve += 1

            else:

                records_without_cve += 1


# ============================================================
# FINAL REPORT
# ============================================================

print("\n" + "=" * 70)
print("QUALYS CVE ANALYSIS")
print("=" * 70)

print(f"Files checked:                  {files_checked:,}")
print(f"Total Qualys records:           {total_records:,}")
print(f"Records WITH CVE:               {records_with_cve:,}")
print(f"Records WITHOUT CVE:            {records_without_cve:,}")
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
# CVE DISTRIBUTION BY COLUMN
# ============================================================

print("\n" + "=" * 70)
print("CVE DISTRIBUTION BY COLUMN")
print("=" * 70)

for column in COLUMNS_TO_CHECK:

    print(
        f"{column:30} → "
        f"{column_record_counts[column]:,} records, "
        f"{column_cve_counts[column]:,} CVE occurrences, "
        f"{len(cves_by_column[column]):,} unique CVEs"
    )


# ============================================================
# TOP 20 CVEs
# ============================================================

print("\n" + "=" * 70)
print("TOP 20 MOST FREQUENT CVEs")
print("=" * 70)

for cve, count in cve_frequency.most_common(20):

    print(
        f"{cve:20} → "
        f"{count:,} occurrences"
    )


# ============================================================
# SAMPLE CVEs BY COLUMN
# ============================================================

print("\n" + "=" * 70)
print("SAMPLE CVEs FOUND IN EACH COLUMN")
print("=" * 70)

for column in COLUMNS_TO_CHECK:

    sample = sorted(cves_by_column[column])[:10]

    print(f"\n{column}:")

    if sample:

        for cve in sample:
            print(f"  {cve}")

    else:

        print("  No CVEs found")


print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)