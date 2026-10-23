from clean_plugins import process_plugins
from clean_qualys import process_qualys


def main():

    print("\n")
    print("=" * 70)
    print("VULNERABILITY RAG - DATA CLEANING PIPELINE")
    print("=" * 70)

    print("\n[1/2] Cleaning Plugin datasets...")
    process_plugins()

    print("\n[2/2] Cleaning Qualys datasets...")
    process_qualys()

    print("\n")
    print("=" * 70)
    print("DATA CLEANING COMPLETED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()