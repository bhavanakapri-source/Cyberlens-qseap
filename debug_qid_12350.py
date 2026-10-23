
import os
from pprint import pprint

from qdrant_client import QdrantClient

from retrieval.cve_search import exact_qid_search
from nvd.nvd_service import enrich_results_with_nvd


client = QdrantClient(
    url=os.environ["QDRANT_URL"],
    api_key=os.environ["QDRANT_API_KEY"],
)

print("\n=== STEP 1: EXACT QID SEARCH ===")

results = exact_qid_search(
    client=client,
    qid=12350,
    limit=10,
)

print("Number of exact results:", len(results))

for index, result in enumerate(results, start=1):
    payload = result.get("payload", {})

    print(f"\n--- Result {index} ---")
    print("QID:", payload.get("QID"))
    print("Title:", payload.get("TITLE"))
    print("CVE_LIST:", payload.get("CVE_LIST"))
    print("cve_list:", payload.get("cve_list"))
    print("CVE:", payload.get("CVE"))
    print("cves:", payload.get("cves"))
    print("Keys:", list(payload.keys()))

print("\n=== STEP 2: NVD ENRICHMENT ===")

evidence = enrich_results_with_nvd(
    results,
    user_query="how to fix QID 12350",
)

print(evidence)
