from pathlib import Path
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

PLUGIN_DIR = PROJECT_ROOT / "data" / "embedding_ready" / "plugins"
QUALYS_DIR = PROJECT_ROOT / "data" / "embedding_ready" / "qualys"


EXPECTED_PLUGIN_COLUMNS = 41
EXPECTED_QUALYS_COLUMNS = 16

EXPECTED_PLUGIN_ROWS = 311_302
EXPECTED_QUALYS_ROWS = 389_817


def verify_dataset(directory, pattern, expected_columns, expected_rows, dataset_name):
    files = sorted(directory.glob(pattern))

    print("=" * 70)
    print(f"{dataset_name.upper()} EMBEDDING-READY VALIDATION")
    print("=" * 70)

    print(f"Files found: {len(files)}")

    total_rows = 0
    all_valid = True

    for file in files:
        df = pd.read_csv(
            file,
            dtype=str,
            keep_default_na=False
        )

        rows = len(df)
        columns = len(df.columns)

        embedding_exists = "embedding_text" in df.columns

        if embedding_exists:
            empty_embedding = (
                df["embedding_text"]
                .astype(str)
                .str.strip()
                .eq("")
                .sum()
            )
        else:
            empty_embedding = rows

        print(f"\nFile: {file.name}")
        print(f"Rows: {rows:,}")
        print(f"Columns: {columns}")
        print(f"Embedding column: {'YES' if embedding_exists else 'NO'}")
        print(f"Empty embedding_text: {empty_embedding:,}")

        if columns != expected_columns:
            print("WARNING: Incorrect column count!")
            all_valid = False

        if not embedding_exists:
            print("WARNING: embedding_text column missing!")
            all_valid = False

        if empty_embedding > 0:
            print("WARNING: Empty embedding_text found!")
            all_valid = False

        total_rows += rows

    print("\n" + "-" * 70)
    print(f"TOTAL {dataset_name.upper()} ROWS: {total_rows:,}")
    print(f"EXPECTED ROWS:       {expected_rows:,}")

    if total_rows != expected_rows:
        print("WARNING: Row count mismatch!")
        all_valid = False
    else:
        print("Row count: PASS")

    print(f"Column count: {'PASS' if all_valid else 'CHECK REQUIRED'}")

    return all_valid


def main():

    print("\n")
    print("=" * 70)
    print("VULNERABILITY RAG - EMBEDDING READY INTEGRITY CHECK")
    print("=" * 70)

    print(f"\nProject root:")
    print(PROJECT_ROOT)

    plugin_valid = verify_dataset(
        PLUGIN_DIR,
        "plugins_part_*.csv",
        EXPECTED_PLUGIN_COLUMNS,
        EXPECTED_PLUGIN_ROWS,
        "Plugin"
    )

    qualys_valid = verify_dataset(
        QUALYS_DIR,
        "qualys_part_*.csv",
        EXPECTED_QUALYS_COLUMNS,
        EXPECTED_QUALYS_ROWS,
        "Qualys"
    )

    print("\n")
    print("=" * 70)
    print("FINAL VALIDATION")
    print("=" * 70)

    if plugin_valid and qualys_valid:
        print("\n✓ PLUGIN DATASET: PASS")
        print("✓ QUALYS DATASET: PASS")
        print("✓ TOTAL RECORDS: 701,119")
        print("\nALL EMBEDDING-READY DATA IS VALID.")
        print("READY FOR SENTENCE TRANSFORMER EMBEDDING GENERATION.")
    else:
        print("\n✗ VALIDATION FAILED")
        print("Fix the problems above before generating embeddings.")

    print("=" * 70)


if __name__ == "__main__":
    main()