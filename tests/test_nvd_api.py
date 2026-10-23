
from nvd.nvd_client import fetch_cve
from nvd.nvd_version_parser import extract_version_info


def main():
    cve_id = "CVE-2021-36934"

    print("Testing NVD API...")
    print("CVE:", cve_id)

    record = fetch_cve(cve_id)

    if record is None:
        print("NVD lookup failed or no matching record was returned.")
        print("Check internet access, API limits, and the CVE ID.")
        return

    result = extract_version_info(record)

    print("\nStatus:", result["status"])
    print("Description:", result["description"])
    print("Version ranges found:", len(result["version_ranges"]))

    for index, version_range in enumerate(
        result["version_ranges"][:10], start=1
    ):
        print(f"\nRange {index}:")
        for key, value in version_range.items():
            if value is not None:
                print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
