import xml.etree.ElementTree as ET
from collections import Counter
import os

INPUT_FOLDER = "input"


def inspect_xml(xml_file):

    print("\n" + "=" * 80)
    print(f"FILE: {os.path.basename(xml_file)}")
    print("=" * 80)

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"❌ Error: {e}")
        return

    print(f"\nRoot element: <{root.tag}>")

    # ---------------------------------------------------------
    # TOTAL ELEMENTS
    # ---------------------------------------------------------

    all_elements = list(root.iter())

    print(f"Total XML elements: {len(all_elements)}")

    # ---------------------------------------------------------
    # TAG COUNTS
    # ---------------------------------------------------------

    counter = Counter(
        element.tag
        for element in all_elements
    )

    print("\n" + "-" * 80)
    print("MOST COMMON TAGS")
    print("-" * 80)

    for tag, count in counter.most_common(30):
        print(f"{tag:50} {count}")

    # ---------------------------------------------------------
    # DIRECT CHILDREN OF ROOT
    # ---------------------------------------------------------

    print("\n" + "-" * 80)
    print("ROOT CHILDREN")
    print("-" * 80)

    root_children = list(root)

    print(f"Number of direct children: {len(root_children)}")

    for child in root_children[:10]:
        print(f"  <{child.tag}>")

    if len(root_children) > 10:
        print("  ...")

    # ---------------------------------------------------------
    # FIRST RECORD STRUCTURE ONLY
    # ---------------------------------------------------------

    if root_children:

        first_record = root_children[0]

        print("\n" + "-" * 80)
        print("FIRST RECORD STRUCTURE")
        print("-" * 80)

        print(f"Record tag: <{first_record.tag}>")

        for child in first_record:

            print(f"\n<{child.tag}>")

            # Show direct children only
            subchildren = list(child)

            if subchildren:

                print("    Contains:")

                for subchild in subchildren[:15]:
                    print(f"      <{subchild.tag}>")

                if len(subchildren) > 15:
                    print("      ...")

            else:

                value = child.text.strip() if child.text else ""

                if len(value) > 200:
                    value = value[:200] + "..."

                print(f"    Value: {value}")

    # ---------------------------------------------------------
    # SAMPLE RECORD VALUES
    # ---------------------------------------------------------

    print("\n" + "-" * 80)
    print("SAMPLE RECORD")
    print("-" * 80)

    if root_children:

        first_record = root_children[0]

        for child in list(first_record)[:30]:

            if not list(child):

                value = child.text.strip() if child.text else ""

                if len(value) > 150:
                    value = value[:150] + "..."

                print(f"{child.tag}: {value}")

    print("\n✅ Inspection complete!")


# =============================================================
# FIND XML FILES
# =============================================================

xml_files = [
    f for f in os.listdir(INPUT_FOLDER)
    if f.lower().endswith(".xml")
]

if not xml_files:

    print("❌ No XML files found in input folder.")

else:

    print(f"Found {len(xml_files)} XML files.")

    for filename in xml_files:

        path = os.path.join(
            INPUT_FOLDER,
            filename
        )

        inspect_xml(path)

print("\n" + "=" * 80)
print("ALL FILES INSPECTED")
print("=" * 80)