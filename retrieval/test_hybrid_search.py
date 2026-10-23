from pathlib import Path
import re

import pandas as pd
from qdrant_client import QdrantClient

from retrieval.query_processor import preprocess_query
from retrieval.cve_extractor import extract_entities
from retrieval.query_embedder import embed_query
from retrieval.hybrid_search import hybrid_search
from retrieval.result_merger import merge_results
from retrieval.reranker import rerank_results


PROJECT_ROOT = Path(__file__).resolve().parents[1]

QDRANT_PATH = PROJECT_ROOT / "qdrant"

TEST_CSV = (
    PROJECT_ROOT
    / "data"
    / "embedding_ready"
    / "plugins"
    / "plugins_part_001.csv"
)


def get_real_cve_from_dataset():

    df = pd.read_csv(
        TEST_CSV,
        nrows=100,
        keep_default_na=False,
    )

    cve_pattern = re.compile(
        r"\bCVE-\d{4}-\d{4,7}\b",
        re.IGNORECASE,
    )

    for _, row in df.iterrows():

        for value in row.values:

            matches = cve_pattern.findall(str(value))

            if matches:
                return matches[0].upper()

    raise RuntimeError(
        "Could not find a CVE in the test dataset."
    )


def main():

    print("=" * 70)
    print("HYBRID RETRIEVAL TEST")
    print("=" * 70)

    # ---------------------------------------------------------
    # CONNECT TO LOCAL QDRANT
    # ---------------------------------------------------------

    client = QdrantClient(
        path=str(QDRANT_PATH)
    )

    print("\nQdrant connected.")

    # ---------------------------------------------------------
    # GET A REAL CVE FROM OUR DATASET
    # ---------------------------------------------------------

    cve = get_real_cve_from_dataset()

    print(f"\nTest CVE: {cve}")

    # ---------------------------------------------------------
    # SIMULATE USER QUERY
    # ---------------------------------------------------------

    original_query = (
        f"How can I fix the vulnerability "
        f"associated with {cve}?"
    )

    print(f"\nUser query:")
    print(original_query)

    # ---------------------------------------------------------
    # STEP 3: PREPROCESS
    # ---------------------------------------------------------

    processed_query = preprocess_query(
        original_query
    )

    print("\nProcessed query:")
    print(processed_query)

    # ---------------------------------------------------------
    # STEP 4: EXTRACT ENTITIES
    # ---------------------------------------------------------

    entities = extract_entities(
        processed_query
    )

    print("\nExtracted entities:")
    print(entities)

    # ---------------------------------------------------------
    # STEP 5: WHOLE QUERY → EMBEDDING
    # ---------------------------------------------------------

    print("\nGenerating 384-D query embedding...")

    query_vector = embed_query(
        processed_query
    )

    print(
        f"Embedding dimension: {len(query_vector)}"
    )

    # ---------------------------------------------------------
    # STEPS 6 + 8:
    # EXACT CVE + SEMANTIC
    # BOTH COLLECTIONS
    # ---------------------------------------------------------

    print("\nRunning hybrid search...")

    hybrid_results = hybrid_search(
        client=client,
        query_vector=query_vector,
        cves=entities["cves"],
        top_k=10,
    )

    cve_results = hybrid_results["cve_results"]
    semantic_results = hybrid_results["semantic_results"]

    print(
        f"\nExact CVE results : {len(cve_results)}"
    )

    print(
        f"Semantic results  : {len(semantic_results)}"
    )

    # ---------------------------------------------------------
    # STEP 9: MERGE
    # ---------------------------------------------------------

    merged_results = merge_results(
        cve_results=cve_results,
        semantic_results=semantic_results,
    )

    print(
        f"Merged unique results: "
        f"{len(merged_results)}"
    )

    # ---------------------------------------------------------
    # STEP 9: RERANK
    # ---------------------------------------------------------

    final_results = rerank_results(
        merged_results,
        top_k=10,
    )

    # ---------------------------------------------------------
    # DISPLAY RESULTS
    # ---------------------------------------------------------

    print("\n" + "=" * 70)
    print("FINAL RERANKED RESULTS")
    print("=" * 70)

    for rank, result in enumerate(
        final_results,
        start=1,
    ):

        payload = result["payload"]

        title = (
            payload.get("TITLE")
            or payload.get("script_name")
            or payload.get("synopsis")
            or payload.get("description")
            or "N/A"
        )

        print(f"\nRank {rank}")
        print(f"Source       : {result['source']}")
        print(f"ID           : {result['id']}")
        print(f"CVE Match    : {result['cve_match']}")
        print(f"Similarity   : {result['similarity']}")
        print(f"Final Score  : {result['final_score']}")
        print(f"Title        : {str(title)[:150]}")

    client.close()

    print("\n" + "=" * 70)
    print("HYBRID RETRIEVAL TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()