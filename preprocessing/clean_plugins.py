import os
import glob
import pandas as pd

from text_cleaner import (
    clean_text,
    clean_identifier,
    normalize_boolean,
    normalize_numeric,
    normalize_list_text,
)
from cve_normalizer import normalize_cve


INPUT_DIR = "xml-to-csv/output"
OUTPUT_DIR = "data/cleaned/plugins"


TEXT_COLUMNS = [
    "script_family",
    "filename",
    "script_version",
    "script_name",
    "script_copyright",
    "description",
    "solution",
    "synopsis",
    "potential_vulnerability",
    "see_also",
    "product_coverage",
    "threat_recency",
    "exploitability_ease",
    "exploit_code_maturity",
    "risk_factor",
    "plugin_type",
]

LIST_COLUMNS = [
    "bids",
    "xrefs",
    "preferences",
    "dependencies",
    "required_keys",
    "excluded_keys",
    "required_ports",
    "required_udp_ports",
]

BOOLEAN_COLUMNS = [
    "exploit_available",
]

NUMERIC_COLUMNS = [
    "cvss_temporal_score",
    "cvss_base_score",
    "vpr_score",
    "age_of_vuln",
    "cvssV3_impactScore",
    "threat_intensity_last_28",
    "threat_sources_last_28",
    "epss_score",
]

IDENTIFIER_COLUMNS = [
    "script_id",
]

DATE_COLUMNS = [
    "vuln_publication_date",
    "plugin_publication_date",
    "plugin_modification_date",
]


def clean_plugins_dataframe(df):
    """
    Clean one Plugins dataframe.

    Important:
    - Do NOT remove records.
    - Preserve remediation information such as solution.
    - Convert missing values to N/A.
    """

    # Text fields
    for column in TEXT_COLUMNS:
        if column in df.columns:
            df[column] = df[column].apply(clean_text)

    # List / multi-value fields
    for column in LIST_COLUMNS:
        if column in df.columns:
            df[column] = df[column].apply(normalize_list_text)

    # Boolean fields
    for column in BOOLEAN_COLUMNS:
        if column in df.columns:
            df[column] = df[column].apply(normalize_boolean)

    # Numeric fields
    for column in NUMERIC_COLUMNS:
        if column in df.columns:
            df[column] = df[column].apply(normalize_numeric)

    # Identifier fields
    for column in IDENTIFIER_COLUMNS:
        if column in df.columns:
            df[column] = df[column].apply(clean_identifier)

    # CVE normalization
    if "cves" in df.columns:
        df["cves"] = df["cves"].apply(normalize_cve)

    # Dates
    for column in DATE_COLUMNS:
        if column in df.columns:
            df[column] = df[column].apply(clean_text)

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


def process_plugins():
    """
    Process all Plugins CSV files.
    """

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    input_files = sorted(
        glob.glob(os.path.join(INPUT_DIR, "plugins_part_*.csv"))
    )

    if not input_files:
        print("No Plugins CSV files found.")
        return

    total_records = 0

    print("=" * 70)
    print("PLUGINS CLEANING")
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

        df = clean_plugins_dataframe(df)

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
    print(f"TOTAL PLUGIN RECORDS: {total_records:,}")
    print("=" * 70)


if __name__ == "__main__":
    process_plugins()