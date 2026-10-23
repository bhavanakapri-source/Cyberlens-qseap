
from unittest.mock import patch

from nvd.nvd_service import enrich_results_with_nvd


def main():
    print("Testing optional NVD enrichment...")

    sample_results = [
        {
            "payload": {
                "cve_list": ["CVE-2021-36934"],
            },
            "cve_match": True,
        }
    ]

    result = enrich_results_with_nvd(
        sample_results,
        user_query="Explain CVE-2021-36934",
    )

    assert "OPTIONAL NVD VERSION EVIDENCE" in result
    assert "CVE-2021-36934" in result
    assert "NVD API" in result

    print("PASS: NVD evidence returned for a CVE.")

    print("Testing failure isolation...")

    with patch(
        "nvd.nvd_service.fetch_cve",
        return_value=None,
    ):
        fallback = enrich_results_with_nvd(
            sample_results,
            user_query="Explain CVE-2021-36934",
        )

    assert "OPTIONAL NVD VERSION EVIDENCE" in fallback
    assert "could not retrieve a record" in fallback.lower()

    print("PASS: NVD failure produces an explanatory fallback.")

    print("Testing product query without a CVE...")

    with patch(
        "nvd.nvd_service.search_cves",
        return_value=[],
    ):
        no_match = enrich_results_with_nvd(
            [],
            user_query="Find vulnerabilities in ExampleProduct",
        )

    assert "OPTIONAL NVD VERSION EVIDENCE" in no_match
    assert "No relevant NVD record" in no_match

    print("PASS: No matching NVD record is reported clearly.")
    print("All NVD service tests passed.")


if __name__ == "__main__":
    main()
