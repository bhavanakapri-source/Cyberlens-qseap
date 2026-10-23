from qdrant_client import QdrantClient

from retrieval.query_pipeline import run_retrieval


def print_results(result):
    print("\n" + "=" * 80)
    print("QUERY")
    print("=" * 80)

    print(result["original_query"])

    print("\nExtracted entities:")
    print(result["entities"])

    print("\n" + "-" * 80)
    print("TOP RESULTS")
    print("-" * 80)

    for rank, item in enumerate(result["results"], start=1):

        payload = item.get("payload", {})

        print(f"\nRank {rank}")
        print(f"Source       : {item['source']}")
        print(f"ID           : {item['id']}")
        print(f"Similarity   : {item.get('similarity')}")
        print(f"CVE Match    : {item.get('cve_match')}")
        print(f"Final Score  : {item.get('final_score'):.4f}")
        print(f"Ranking      : {item.get('ranking_details')}")

        # Useful fields from Qualys
        if item["source"] == "qualys_vulnerabilities":
            print(f"Title        : {payload.get('title', 'N/A')}")
            print(f"Vendor       : {payload.get('software_vendor', 'N/A')}")
            print(f"Product      : {payload.get('software_product', 'N/A')}")
            print(f"Severity     : {payload.get('severity_level', 'N/A')}")
            print(f"Patchable    : {payload.get('patchable', 'N/A')}")

        # Useful fields from Plugins
        else:
            print(f"Script Name  : {payload.get('script_name', 'N/A')}")
            print(f"Risk Factor  : {payload.get('risk_factor', 'N/A')}")
            print(f"Product Cov. : {payload.get('product_coverage', 'N/A')}")
            print(f"Exploit      : {payload.get('exploit_available', 'N/A')}")
            print(f"Solution     : {payload.get('solution', 'N/A')[:200]}")


def main():

    client = QdrantClient(path="qdrant")

    queries = [
        "How to fix the most critical Windows vulnerabilities?",

        "Which Windows vulnerabilities are exploitable and need immediate remediation?",

        "How can I fix CVE-1999-0455?",
    ]

    print("\n")
    print("=" * 80)
    print("PAYLOAD-AWARE HYBRID RETRIEVAL TEST")
    print("=" * 80)

    for query in queries:

        result = run_retrieval(
            client=client,
            original_query=query,
            top_k_search=100,
            top_k_final=10,
        )

        print_results(result)

    print("\n")
    print("=" * 80)
    print("ALL TESTS COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()