import os
import xml.etree.ElementTree as ET


def count_records(xml_file, record_tag):
    count = 0

    for event, element in ET.iterparse(
        xml_file,
        events=("end",)
    ):
        if element.tag.endswith(record_tag):
            count += 1
            element.clear()

    return count


# ============================================================
# FILES
# ============================================================

plugins_file = os.path.join("input", "plugins.xml")
qualys_file = os.path.join("input", "qualys.xml")


# ============================================================
# COUNT
# ============================================================

print("=" * 60)
print("XML DATASET RECORD COUNT")
print("=" * 60)

print("\nCounting plugins.xml...")

plugins_count = count_records(
    plugins_file,
    "nasl"
)

print(
    f"plugins.xml → {plugins_count:,} records"
)


print("\nCounting qualys.xml...")

qualys_count = count_records(
    qualys_file,
    "VULN"
)

print(
    f"qualys.xml → {qualys_count:,} records"
)


print("\n" + "=" * 60)
print("FINAL COUNT")
print("=" * 60)

print(
    f"Plugins dataset : {plugins_count:,} records"
)

print(
    f"Qualys dataset  : {qualys_count:,} records"
)

print("=" * 60)