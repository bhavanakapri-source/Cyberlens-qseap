import os
import csv
import xml.etree.ElementTree as ET


# ============================================================
# CONFIGURATION
# ============================================================

# Change this if your Qualys XML has a different filename
INPUT_FILE = os.path.join("input", "qualys.xml")

OUTPUT_DIR = os.path.join("output")

# Number of <VULN> records in each CSV file
RECORDS_PER_FILE = 50000


# ============================================================
# CSV COLUMNS
# ============================================================

COLUMNS = [
    # --------------------------------------------------------
    # Basic vulnerability information
    # --------------------------------------------------------

    "QID",
    "VULN_TYPE",
    "SEVERITY_LEVEL",
    "TITLE",
    "CATEGORY",

    "LAST_SERVICE_MODIFICATION_DATETIME",
    "PUBLISHED_DATETIME",

    "PATCHABLE",

    # --------------------------------------------------------
    # Software information
    # --------------------------------------------------------

    "SOFTWARE_PRODUCT",
    "SOFTWARE_VENDOR",

    # --------------------------------------------------------
    # Vulnerability details
    # --------------------------------------------------------

    "DIAGNOSIS",

    "PCI_FLAG",

    "SUPPORTED_MODULES",

    # --------------------------------------------------------
    # Discovery
    # --------------------------------------------------------

    "DISCOVERY_REMOTE",

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    "IS_DISABLED",
]


# ============================================================
# CLEAN TEXT
# ============================================================

def clean_text(text):
    """
    Clean XML text before writing it into CSV.

    Removes:
    - New lines
    - Carriage returns
    - Tabs
    - Repeated spaces
    - Leading/trailing spaces

    This keeps each vulnerability as one clean row.
    """

    if text is None:
        return ""

    text = str(text)

    # Replace line breaks
    text = text.replace("\n", " ")

    # Replace carriage returns
    text = text.replace("\r", " ")

    # Replace tabs
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
    Remove XML namespace if present.
    """

    if "}" in tag:
        return tag.split("}", 1)[1]

    return tag


# ============================================================
# GET TEXT
# ============================================================

def get_text(element):
    """
    Safely extract text from an XML element
    and clean it.
    """

    if element is None:
        return ""

    return clean_text(
        "".join(element.itertext())
    )


# ============================================================
# GET DIRECT CHILD TEXT
# ============================================================

def get_child_text(parent, child_name):
    """
    Get the text of a direct child element.

    Example:

    <TITLE>
        DNS Host Name
    </TITLE>

    returns:

    DNS Host Name
    """

    for child in parent:

        if clean_tag(child.tag) == child_name:

            return get_text(child)

    return ""


# ============================================================
# GET SOFTWARE INFORMATION
# ============================================================

def get_software_information(vuln):
    """
    Extract PRODUCT and VENDOR from:

    <SOFTWARE_LIST>
        <SOFTWARE>
            <PRODUCT>...</PRODUCT>
            <VENDOR>...</VENDOR>
        </SOFTWARE>
    </SOFTWARE_LIST>

    If multiple SOFTWARE entries exist, they are joined
    using '; ' so everything remains in the same row.
    """

    products = []
    vendors = []

    # Find SOFTWARE_LIST
    for child in vuln:

        if clean_tag(child.tag) != "SOFTWARE_LIST":
            continue

        # Find SOFTWARE entries
        for software in child:

            if clean_tag(software.tag) != "SOFTWARE":
                continue

            product = ""
            vendor = ""

            # Read PRODUCT and VENDOR
            for item in software:

                tag = clean_tag(item.tag)

                if tag == "PRODUCT":
                    product = get_text(item)

                elif tag == "VENDOR":
                    vendor = get_text(item)

            if product:
                products.append(product)

            if vendor:
                vendors.append(vendor)

    return (
        "; ".join(products),
        "; ".join(vendors)
    )


# ============================================================
# GET DISCOVERY INFORMATION
# ============================================================

def get_discovery_remote(vuln):
    """
    Extract:

    <DISCOVERY>
        <REMOTE>1</REMOTE>
    </DISCOVERY>
    """

    for child in vuln:

        if clean_tag(child.tag) != "DISCOVERY":
            continue

        for item in child:

            if clean_tag(item.tag) == "REMOTE":

                return get_text(item)

    return ""


# ============================================================
# PROCESS ONE <VULN> RECORD
# ============================================================

def process_vulnerability(vuln):

    row = {}

    # --------------------------------------------------------
    # BASIC INFORMATION
    # --------------------------------------------------------

    row["QID"] = get_child_text(
        vuln,
        "QID"
    )

    row["VULN_TYPE"] = get_child_text(
        vuln,
        "VULN_TYPE"
    )

    row["SEVERITY_LEVEL"] = get_child_text(
        vuln,
        "SEVERITY_LEVEL"
    )

    row["TITLE"] = get_child_text(
        vuln,
        "TITLE"
    )

    row["CATEGORY"] = get_child_text(
        vuln,
        "CATEGORY"
    )

    row["LAST_SERVICE_MODIFICATION_DATETIME"] = get_child_text(
        vuln,
        "LAST_SERVICE_MODIFICATION_DATETIME"
    )

    row["PUBLISHED_DATETIME"] = get_child_text(
        vuln,
        "PUBLISHED_DATETIME"
    )

    row["PATCHABLE"] = get_child_text(
        vuln,
        "PATCHABLE"
    )

    # --------------------------------------------------------
    # SOFTWARE
    # --------------------------------------------------------

    product, vendor = get_software_information(
        vuln
    )

    row["SOFTWARE_PRODUCT"] = product
    row["SOFTWARE_VENDOR"] = vendor

    # --------------------------------------------------------
    # VULNERABILITY DETAILS
    # --------------------------------------------------------

    row["DIAGNOSIS"] = get_child_text(
        vuln,
        "DIAGNOSIS"
    )

    row["PCI_FLAG"] = get_child_text(
        vuln,
        "PCI_FLAG"
    )

    row["SUPPORTED_MODULES"] = get_child_text(
        vuln,
        "SUPPORTED_MODULES"
    )

    # --------------------------------------------------------
    # DISCOVERY
    # --------------------------------------------------------

    row["DISCOVERY_REMOTE"] = get_discovery_remote(
        vuln
    )

    # --------------------------------------------------------
    # STATUS
    # --------------------------------------------------------

    row["IS_DISABLED"] = get_child_text(
        vuln,
        "IS_DISABLED"
    )

    # --------------------------------------------------------
    # FINAL CLEANUP
    # --------------------------------------------------------

    # Make sure every value is clean and every column exists.

    for column in COLUMNS:

        if column not in row:

            row[column] = ""

        else:

            row[column] = clean_text(
                row[column]
            )

    return row


# ============================================================
# CREATE CSV FILE
# ============================================================

def create_csv_writer(file_number):

    filename = (
        f"qualys_part_{file_number:03d}.csv"
    )

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

    # Write headers
    writer.writeheader()

    print()
    print("-" * 70)
    print(f"Created: {filename}")
    print("-" * 70)

    return csv_file, writer


# ============================================================
# XML → CSV CHUNKS
# ============================================================

def xml_to_csv_chunks():

    print()
    print("=" * 70)
    print("QUALYS XML → CLEAN CHUNKED CSV")
    print("=" * 70)

    # --------------------------------------------------------
    # CHECK INPUT FILE
    # --------------------------------------------------------

    if not os.path.exists(INPUT_FILE):

        print()
        print("ERROR: Input XML file not found!")
        print()
        print("Expected:")
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

        tag = clean_tag(
            element.tag
        )

        # ----------------------------------------------------
        # ONLY PROCESS COMPLETE <VULN> RECORDS
        # ----------------------------------------------------

        if tag != "VULN":

            continue

        # ----------------------------------------------------
        # CREATE NEW CSV FILE WHEN NEEDED
        # ----------------------------------------------------

        if writer is None:

            file_number += 1

            csv_file, writer = create_csv_writer(
                file_number
            )

            current_file_records = 0

        # ----------------------------------------------------
        # PROCESS VULNERABILITY
        # ----------------------------------------------------

        row = process_vulnerability(
            element
        )

        # ----------------------------------------------------
        # WRITE ROW
        # ----------------------------------------------------

        writer.writerow(
            row
        )

        total_records += 1

        current_file_records += 1

        # ----------------------------------------------------
        # PROGRESS
        # ----------------------------------------------------

        if total_records % 1000 == 0:

            print(
                f"Processed: "
                f"{total_records:,} records",
                end="\r"
            )

        # ----------------------------------------------------
        # CLOSE CURRENT CSV WHEN FULL
        # ----------------------------------------------------

        if current_file_records >= RECORDS_PER_FILE:

            csv_file.close()

            print()

            print(
                f"Completed: "
                f"qualys_part_{file_number:03d}.csv"
                f" → "
                f"{current_file_records:,} records"
            )

            csv_file = None
            writer = None

        # ----------------------------------------------------
        # FREE XML MEMORY
        # ----------------------------------------------------

        element.clear()

    # --------------------------------------------------------
    # CLOSE FINAL CSV
    # --------------------------------------------------------

    if csv_file is not None:

        csv_file.close()

        print()

        print(
            f"Completed: "
            f"qualys_part_{file_number:03d}.csv"
            f" → "
            f"{current_file_records:,} records"
        )

    # --------------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("CONVERSION COMPLETED")
    print("=" * 70)

    print()
    print(
        f"Total records processed : "
        f"{total_records:,}"
    )

    print(
        f"CSV files created       : "
        f"{file_number}"
    )

    print(
        f"Records per file        : "
        f"{RECORDS_PER_FILE:,}"
    )

    print(
        f"Output directory        : "
        f"{OUTPUT_DIR}"
    )

    print()
    print("Files created:")

    for i in range(
        1,
        file_number + 1
    ):

        filename = (
            f"qualys_part_{i:03d}.csv"
        )

        print(
            f"    {filename}"
        )

    print()
    print("=" * 70)


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":

    xml_to_csv_chunks()