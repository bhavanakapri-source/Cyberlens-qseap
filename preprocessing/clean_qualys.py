import os
import glob
import pandas as pd

from text_cleaner import (
    clean_text,
    clean_identifier,
    normalize_boolean,
)
from cve_normalizer import normalize_cve


INPUT_DIR = "xml-to-csv/output"
OUTPUT_DIR = "data/cleaned/qualys"


TEXT_COLUMNS = [
    "VULN_TYPE",
    "TITLE",
    "CATEGORY",
    "SOFTWARE_PRODUCT",
    "SOFTWARE_VENDOR",
    "DIAGNOSIS",
    "SUPPORTED_MODULES",
]

IDENTIFIER_COLUMNS = [
    "QID",
]

BOOLEAN_COLUMNS = [
    "PATCHABLE",
    "PCI_FLAG",
    "DISCOVERY_REMOTE",
    "IS_DISABLED",
]

DATE_COLUMNS = [
    "LAST_SERVICE_MODIFICATION_DATETIME",
    "PUBLISHED_DATETIME",
]


def clean_qualys_dataframe(df):
    """
    Clean one Qualys dataframe.

    Important:
    - Do NOT remove records.
    - Preserve DIAGNOSIS because it contains remediation information.
    - Preserve PATCHABLE.
    - Convert missing values to N/A.
    """

    # Text fields
    for column in TEXT_COLUMNS:
        if column in df.columns:
            df[column] = df[column].apply(clean_text)

    # Identifier fields
    for column in IDENTIFIER_COLUMNS:
        if column in df.columns:
            df[column] = df[column].apply(clean_identifier)

    # Boolean fields
    for column in BOOLEAN_COLUMNS:
        if column in df.columns:
            df[column] = df[column].apply(normalize_boolean)

    # Dates
    for column in DATE_COLUMNS:
        if column in df.columns:
            df[column] = df[column].apply(clean_text)

    # If CVE information exists inside relevant text fields,
    # normalization is handled later during structured extraction.
    # We intentionally do NOT remove or alter the original text.

    # Final missing-value cleanup
    df = df.replace(
        [
            "",
            "nan",
            "NaN",
            "NAN",
            "None",
            "none",
            "NONE",
            "NULL",
            "null",
            "nil",
            "NIL",
            "NA",
            "na",
            "n/a",
            "N/A",
        ],
        "N/A",
    )

    df = df.fillna("N/A")

    return df


def process_qualys():
    """
    Process all Qualys CSV files.
    """

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    input_files = sorted(
        glob.glob(os.path.join(INPUT_DIR, "qualys_part_*.csv"))
    )

    if not input_files:
        print("No Qualys CSV files found.")
        return

    total_records = 0

    print("=" * 70)
    print("QUALYS CLEANING")
    print("=" * 70)

    for input_file in input_files:

        filename = os.path.basename(input_file)

        print(f"\nProcessing: {filename}")

        df = pd.read_csv(
            input_file,
            dtype=str,
            keep_default_na=False,
        )

        original_count = len(df)

        df = clean_qualys_dataframe(df)

        output_file = os.path.join(
            OUTPUT_DIR,
            filename
        )

        df.to_csv(
            output_file,
            index=False,
            encoding="utf-8"
        )

        total_records += len(df)

        print(f"Records: {original_count:,}")
        print(f"Saved:   {output_file}")

    print("\n" + "=" * 70)
    print(f"TOTAL QUALYS RECORDS: {total_records:,}")
    print("=" * 70)


if __name__ == "__main__":
    process_qualys()