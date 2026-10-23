import os
import csv
import xml.etree.ElementTree as ET


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_FILE = os.path.join("input", "plugins.xml")
OUTPUT_DIR = os.path.join("output")

# Number of NASL records in each CSV file
RECORDS_PER_FILE = 50000


# ============================================================
# CSV COLUMNS
# ============================================================

COLUMNS = [
    "script_family",
    "filename",
    "script_version",
    "script_name",
    "script_copyright",
    "script_id",

    "cves",
    "bids",
    "xrefs",

    "preferences",
    "dependencies",
    "required_keys",
    "excluded_keys",
    "required_ports",
    "required_udp_ports",

    "exploitability_ease",
    "vuln_publication_date",
    "cvss_temporal_vector",
    "solution",
    "risk_factor",
    "cvss_temporal_score",
    "description",
    "plugin_publication_date",
    "cvss_vector",
    "plugin_type",
    "synopsis",
    "potential_vulnerability",
    "see_also",
    "exploit_available",
    "plugin_modification_date",
    "cvss_base_score",
    "vpr_score",
    "age_of_vuln",
    "cvssV3_impactScore",
    "exploit_code_maturity",
    "product_coverage",
    "threat_intensity_last_28",
    "threat_recency",
    "threat_sources_last_28",
    "epss_score",
]


# ============================================================
# CLEAN TEXT
# ============================================================

def clean_text(text):
    """
    Clean text before putting it into CSV.

    Removes:
    - New lines
    - Carriage returns
    - Tabs
    - Repeated spaces
    - Leading/trailing spaces

    This keeps every record compact when opened in Excel.
    """

    if not text:
        return ""

    text = str(text)

    # Replace line breaks and tabs with spaces
    text = text.replace("\n", " ")
    text = text.replace("\r", " ")
    text = text.replace("\t", " ")

    # Remove repeated whitespace
    text = " ".join(text.split())

    # Remove leading/trailing spaces
    return text.strip()


# ============================================================
# CLEAN XML TAG
# ============================================================

def clean_tag(tag):
    """
    Remove XML namespace if one exists.
    """

    if "}" in tag:
        return tag.split("}", 1)[1]

    return tag


# ============================================================
# GET ELEMENT TEXT
# ============================================================

def get_text(element):
    """
    Safely extract and clean text from an XML element.
    """

    if element is None:
        return ""

    return clean_text(element.text)


# ============================================================
# GET CHILD TEXT
# ============================================================

def get_child_text(parent, child_name):
    """
    Get text from a direct child element.

    Example:

    <script_name>
        Microsoft IIS...
    </script_name>
    """

    for child in parent:

        if clean_tag(child.tag) == child_name:
            return get_text(child)

    return ""


# ============================================================
# GET MULTIPLE VALUES
# ============================================================

def get_multiple_values(parent, container_name, item_name):
    """
    Extract multiple values from nested XML.

    Example:

    <cves>
        <cve>CVE-1999-0449</cve>
        <cve>CVE-2000-1234</cve>
    </cves>

    Output:

    CVE-1999-0449; CVE-2000-1234
    """

    for container in parent:

        if clean_tag(container.tag) != container_name:
            continue

        values = []

        for item in container:

            if clean_tag(item.tag) == item_name:

                value = get_text(item)

                if value:
                    values.append(value)

        return "; ".join(values)

    return ""


# ============================================================
# GET ATTRIBUTE VALUES
# ============================================================

def get_attribute_values(nasl_element):
    """
    Extract:

    <attribute>
        <name>risk_factor</name>
        <value>Medium</value>
    </attribute>

    into:

    {
        "risk_factor": "Medium"
    }
    """

    attributes = {}

    for child in nasl_element:

        if clean_tag(child.tag) != "attributes":
            continue

        for attribute in child:

            if clean_tag(attribute.tag) != "attribute":
                continue

            name = ""
            value = ""

            for item in attribute:

                tag = clean_tag(item.tag)

                if tag == "name":
                    name = get_text(item)

                elif tag == "value":
                    value = get_text(item)

            if name:
                attributes[name] = value

    return attributes


# ============================================================
# PROCESS ONE <nasl> RECORD
# ============================================================

def process_nasl(nasl):

    row = {}

    # --------------------------------------------------------
    # BASIC INFORMATION
    # --------------------------------------------------------

    row["script_family"] = get_child_text(
        nasl,
        "script_family"
    )

    row["filename"] = get_child_text(
        nasl,
        "filename"
    )

    row["script_version"] = get_child_text(
        nasl,
        "script_version"
    )

    row["script_name"] = get_child_text(
        nasl,
        "script_name"
    )

    row["script_copyright"] = get_child_text(
        nasl,
        "script_copyright"
    )

    row["script_id"] = get_child_text(
        nasl,
        "script_id"
    )

    # --------------------------------------------------------
    # MULTIPLE VALUE FIELDS
    # --------------------------------------------------------

    row["cves"] = get_multiple_values(
        nasl,
        "cves",
        "cve"
    )

    row["bids"] = get_multiple_values(
        nasl,
        "bids",
        "bid"
    )

    row["xrefs"] = get_multiple_values(
        nasl,
        "xrefs",
        "xref"
    )

    row["preferences"] = get_multiple_values(
        nasl,
        "preferences",
        "preference"
    )

    row["dependencies"] = get_multiple_values(
        nasl,
        "dependencies",
        "dependency"
    )

    row["required_keys"] = get_multiple_values(
        nasl,
        "required_keys",
        "required_key"
    )

    row["excluded_keys"] = get_multiple_values(
        nasl,
        "excluded_keys",
        "excluded_key"
    )

    row["required_ports"] = get_multiple_values(
        nasl,
        "required_ports",
        "required_port"
    )

    row["required_udp_ports"] = get_multiple_values(
        nasl,
        "required_udp_ports",
        "required_udp_port"
    )

    # --------------------------------------------------------
    # ATTRIBUTES
    # --------------------------------------------------------

    attributes = get_attribute_values(nasl)

    for column in COLUMNS:

        if column in attributes:
            row[column] = attributes[column]

    # --------------------------------------------------------
    # FINAL CLEANUP
    # --------------------------------------------------------
    #
    # Make sure EVERY value is cleaned before writing
    # to the CSV.
    #
    # This is important for Excel display.
    # --------------------------------------------------------

    for column in COLUMNS:

        if column not in row:
            row[column] = ""

        else:
            row[column] = clean_text(row[column])

    return row


# ============================================================
# CREATE NEW CSV FILE
# ============================================================

def create_csv_writer(file_number):

    filename = f"plugins_part_{file_number:03d}.csv"

    filepath = os.path.join(
        OUTPUT_DIR,
        filename
    )

    csv_file = open(
        filepath,
        "w",
        newline="",
        encoding="utf-8-sig"
    )

    writer = csv.DictWriter(
        csv_file,
        fieldnames=COLUMNS,
        extrasaction="ignore",
        quoting=csv.QUOTE_MINIMAL
    )

    # Write column headers
    writer.writeheader()

    print()
    print("-" * 70)
    print(f"Created: {filename}")
    print("-" * 70)

    return csv_file, writer


# ============================================================
# MAIN XML → CSV CHUNK CONVERSION
# ============================================================

def xml_to_csv_chunks():

    print()
    print("=" * 70)
    print("PLUGINS XML → CLEAN CHUNKED CSV")
    print("=" * 70)

    # --------------------------------------------------------
    # CHECK INPUT
    # --------------------------------------------------------

    if not os.path.exists(INPUT_FILE):

        print()
        print("ERROR: Input file not found!")
        print()
        print(f"Expected file:")
        print(f"    {INPUT_FILE}")
        print()

        return

    # --------------------------------------------------------
    # CREATE OUTPUT DIRECTORY
    # --------------------------------------------------------

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    print()
    print("Input file:")
    print(f"    {INPUT_FILE}")

    print()
    print("Output directory:")
    print(f"    {OUTPUT_DIR}")

    print()
    print("Records per CSV:")
    print(f"    {RECORDS_PER_FILE:,}")

    print()
    print("Starting conversion...")
    print()

    # --------------------------------------------------------
    # VARIABLES
    # --------------------------------------------------------

    total_records = 0

    current_file_records = 0

    file_number = 0

    csv_file = None
    writer = None

    # --------------------------------------------------------
    # STREAM XML
    # --------------------------------------------------------

    for event, element in ET.iterparse(
        INPUT_FILE,
        events=("end",)
    ):

        tag = clean_tag(element.tag)

        # ----------------------------------------------------
        # ONLY PROCESS <nasl>
        # ----------------------------------------------------

        if tag != "nasl":
            continue

        # ----------------------------------------------------
        # CREATE NEW CSV WHEN NEEDED
        # ----------------------------------------------------

        if writer is None:

            file_number += 1

            csv_file, writer = create_csv_writer(
                file_number
            )

            current_file_records = 0

        # ----------------------------------------------------
        # PROCESS XML RECORD
        # ----------------------------------------------------

        row = process_nasl(element)

        # ----------------------------------------------------
        # WRITE CSV ROW
        # ----------------------------------------------------

        writer.writerow(row)

        total_records += 1

        current_file_records += 1

        # ----------------------------------------------------
        # SHOW PROGRESS
        # ----------------------------------------------------

        if total_records % 1000 == 0:

            print(
                f"Processed: {total_records:,} records",
                end="\r"
            )

        # ----------------------------------------------------
        # CLOSE CSV WHEN LIMIT IS REACHED
        # ----------------------------------------------------

        if current_file_records >= RECORDS_PER_FILE:

            csv_file.close()

            print()
            print(
                f"Completed: plugins_part_"
                f"{file_number:03d}.csv"
                f" → {current_file_records:,} records"
            )

            csv_file = None
            writer = None

        # ----------------------------------------------------
        # FREE XML MEMORY
        # ----------------------------------------------------

        element.clear()

    # --------------------------------------------------------
    # CLOSE LAST CSV
    # --------------------------------------------------------

    if csv_file is not None:

        csv_file.close()

        print()

        print(
            f"Completed: plugins_part_"
            f"{file_number:03d}.csv"
            f" → {current_file_records:,} records"
        )

    # --------------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("CONVERSION COMPLETED")
    print("=" * 70)

    print()
    print(f"Total records processed : {total_records:,}")
    print(f"CSV files created       : {file_number}")
    print(f"Records per file        : {RECORDS_PER_FILE:,}")
    print(f"Output directory        : {OUTPUT_DIR}")

    print()
    print("Files created:")

    for i in range(1, file_number + 1):

        filename = f"plugins_part_{i:03d}.csv"

        print(f"    {filename}")

    print()
    print("=" * 70)


# ============================================================
# PROGRAM START
# ============================================================

if __name__ == "__main__":

    xml_to_csv_chunks()