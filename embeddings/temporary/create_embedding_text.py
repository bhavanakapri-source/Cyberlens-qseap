from pathlib import Path
import pandas as pd


# ============================================================
# PROJECT PATHS
# ============================================================

# This file is:
# RAG/embeddings/temporary/create_embedding_text.py
#
# parents[0] = temporary
# parents[1] = embeddings
# parents[2] = RAG

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PLUGIN_INPUT_DIR = PROJECT_ROOT / "data" / "cleaned" / "plugins"
QUALYS_INPUT_DIR = PROJECT_ROOT / "data" / "cleaned" / "qualys"

PLUGIN_OUTPUT_DIR = PROJECT_ROOT / "data" / "embedding_ready" / "plugins"
QUALYS_OUTPUT_DIR = PROJECT_ROOT / "data" / "embedding_ready" / "qualys"


# ============================================================
# PLUGIN FIELDS USED FOR SEMANTIC EMBEDDING
# ============================================================

PLUGIN_EMBEDDING_FIELDS = [
    "script_family",
    "filename",
    "script_version",
    "script_name",
    "cves",
    "bids",
    "xrefs",
    "dependencies",
    "required_ports",
    "required_udp_ports",
    "exploitability_ease",
    "solution",
    "risk_factor",
    "description",
    "cvss_vector",
    "plugin_type",
    "synopsis",
    "potential_vulnerability",
    "see_also",
    "exploit_available",
    "product_coverage",
    "exploit_code_maturity",
]


# ============================================================
# QUALYS FIELDS USED FOR SEMANTIC EMBEDDING
# ============================================================

QUALYS_EMBEDDING_FIELDS = [
    "VULN_TYPE",
    "SEVERITY_LEVEL",
    "TITLE",
    "CATEGORY",
    "PATCHABLE",
    "SOFTWARE_PRODUCT",
    "SOFTWARE_VENDOR",
    "DIAGNOSIS",
    "SUPPORTED_MODULES",
]


# ============================================================
# FIELD LABELS
# ============================================================

PLUGIN_FIELD_LABELS = {
    "script_family": "Script Family",
    "filename": "Plugin Filename",
    "script_version": "Plugin Version",
    "script_name": "Vulnerability",
    "cves": "CVE",
    "bids": "Bugtraq IDs",
    "xrefs": "External References",
    "dependencies": "Dependencies",
    "required_ports": "Required TCP Ports",
    "required_udp_ports": "Required UDP Ports",
    "exploitability_ease": "Exploitability Ease",
    "solution": "Remediation / Solution",
    "risk_factor": "Risk Factor",
    "description": "Description",
    "cvss_vector": "CVSS Vector",
    "plugin_type": "Plugin Type",
    "synopsis": "Synopsis",
    "potential_vulnerability": "Potential Vulnerability",
    "see_also": "See Also",
    "exploit_available": "Exploit Available",
    "product_coverage": "Product Coverage",
    "exploit_code_maturity": "Exploit Code Maturity",
}


QUALYS_FIELD_LABELS = {
    "VULN_TYPE": "Vulnerability Type",
    "SEVERITY_LEVEL": "Severity Level",
    "TITLE": "Vulnerability",
    "CATEGORY": "Category",
    "PATCHABLE": "Patchable",
    "SOFTWARE_PRODUCT": "Software Product",
    "SOFTWARE_VENDOR": "Software Vendor",
    "DIAGNOSIS": "Diagnosis / Remediation",
    "SUPPORTED_MODULES": "Supported Modules",
}


# ============================================================
# SAFE VALUE
# ============================================================

def safe_value(value):
    """
    Convert a dataframe value into safe text.

    Missing values remain represented as N/A.
    """

    if pd.isna(value):
        return "N/A"

    value = str(value).strip()

    if not value:
        return "N/A"

    return value


# ============================================================
# CREATE PLUGIN EMBEDDING TEXT
# ============================================================

def create_plugin_embedding_text(row):
    """
    Create semantic embedding text for one Plugin record.

    IMPORTANT:
    This function does NOT delete or modify any original column.

    The resulting embedding_text is only an additional column.
    """

    sections = []

    for field in PLUGIN_EMBEDDING_FIELDS:

        if field not in row.index:
            continue

        value = safe_value(row[field])

        label = PLUGIN_FIELD_LABELS.get(
            field,
            field
        )

        sections.append(
            f"{label}: {value}"
        )

    return "\n".join(sections)


# ============================================================
# CREATE QUALYS EMBEDDING TEXT
# ============================================================

def create_qualys_embedding_text(row):
    """
    Create semantic embedding text for one Qualys record.

    IMPORTANT:
    This function does NOT delete or modify any original column.

    The resulting embedding_text is only an additional column.
    """

    sections = []

    for field in QUALYS_EMBEDDING_FIELDS:

        if field not in row.index:
            continue

        value = safe_value(row[field])

        label = QUALYS_FIELD_LABELS.get(
            field,
            field
        )

        sections.append(
            f"{label}: {value}"
        )

    return "\n".join(sections)


# ============================================================
# PROCESS PLUGIN FILES
# ============================================================

def process_plugins():
    """
    Create embedding_text for all cleaned Plugin CSV files.

    Original cleaned files are NOT modified.
    """

    PLUGIN_OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    input_files = sorted(
        PLUGIN_INPUT_DIR.glob(
            "plugins_part_*.csv"
        )
    )

    if not input_files:
        print("ERROR: No cleaned Plugin files found.")
        print(f"Expected location: {PLUGIN_INPUT_DIR}")
        return

    print("=" * 70)
    print("PLUGIN EMBEDDING TEXT PREPARATION")
    print("=" * 70)

    total_records = 0

    for input_file in input_files:

        print(f"\nProcessing: {input_file.name}")

        df = pd.read_csv(
            input_file,
            dtype=str,
            keep_default_na=False
        )

        original_columns = len(df.columns)
        original_records = len(df)

        # Create ONLY one new column.
        df["embedding_text"] = df.apply(
            create_plugin_embedding_text,
            axis=1
        )

        output_file = (
            PLUGIN_OUTPUT_DIR /
            input_file.name
        )

        df.to_csv(
            output_file,
            index=False,
            encoding="utf-8"
        )

        total_records += len(df)

        print(f"Records:          {original_records:,}")
        print(f"Original columns: {original_columns}")
        print(f"Final columns:    {len(df.columns)}")
        print(f"Saved:            {output_file}")

    print("\n" + "=" * 70)
    print(f"TOTAL PLUGIN RECORDS: {total_records:,}")
    print("=" * 70)


# ============================================================
# PROCESS QUALYS FILES
# ============================================================

def process_qualys():
    """
    Create embedding_text for all cleaned Qualys CSV files.

    Original cleaned files are NOT modified.
    """

    QUALYS_OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    input_files = sorted(
        QUALYS_INPUT_DIR.glob(
            "qualys_part_*.csv"
        )
    )

    if not input_files:
        print("ERROR: No cleaned Qualys files found.")
        print(f"Expected location: {QUALYS_INPUT_DIR}")
        return

    print("=" * 70)
    print("QUALYS EMBEDDING TEXT PREPARATION")
    print("=" * 70)

    total_records = 0

    for input_file in input_files:

        print(f"\nProcessing: {input_file.name}")

        df = pd.read_csv(
            input_file,
            dtype=str,
            keep_default_na=False
        )

        original_columns = len(df.columns)
        original_records = len(df)

        # Create ONLY one new column.
        df["embedding_text"] = df.apply(
            create_qualys_embedding_text,
            axis=1
        )

        output_file = (
            QUALYS_OUTPUT_DIR /
            input_file.name
        )

        df.to_csv(
            output_file,
            index=False,
            encoding="utf-8"
        )

        total_records += len(df)

        print(f"Records:          {original_records:,}")
        print(f"Original columns: {original_columns}")
        print(f"Final columns:    {len(df.columns)}")
        print(f"Saved:            {output_file}")

    print("\n" + "=" * 70)
    print(f"TOTAL QUALYS RECORDS: {total_records:,}")
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("VULNERABILITY RAG - EMBEDDING TEXT PREPARATION")
    print("=" * 70)

    print("\nProject root:")
    print(PROJECT_ROOT)

    print("\n[1/2] Preparing Plugin embedding text...")
    process_plugins()

    print("\n[2/2] Preparing Qualys embedding text...")
    process_qualys()

    print()
    print("=" * 70)
    print("EMBEDDING TEXT PREPARATION COMPLETED")
    print("=" * 70)