"""
End-to-end CyberLens RAG + Gemini test.

Flow:
    User Query
        ↓
    Retrieval Pipeline
        ↓
    Qdrant
        ↓
    Reranking
        ↓
    Context Builder
        ↓
    Prompt Builder
        ↓
    Gemini
        ↓
    Final Answer

Run from project root:

    python -m llm.test_llm
"""

from pathlib import Path

from qdrant_client import QdrantClient

from retrieval.query_pipeline import run_retrieval
from retrieval.context_builder import build_context

from .prompt_builder import build_prompt
from .gemini_client import generate_answer, GEMINI_MODEL


# ============================================================
# CONFIGURATION
# ============================================================

QDRANT_PATH = (
    Path(__file__).resolve().parents[1] / "qdrant"
)

TOP_K_SEARCH = 100
TOP_K_FINAL = 10


# ============================================================
# TEST QUERY
# ============================================================

TEST_QUERY = "How can I fix CVE-1999-0455?"


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 80)
    print("CYBERLENS RAG + GEMINI END-TO-END TEST")
    print("=" * 80)

    print()
    print("Gemini Model:", GEMINI_MODEL)
    print("Qdrant Path:", QDRANT_PATH)

    print()
    print("-" * 80)
    print("USER QUERY")
    print("-" * 80)
    print(TEST_QUERY)

    # ========================================================
    # CONNECT TO QDRANT
    # ========================================================

    print()
    print("-" * 80)
    print("CONNECTING TO QDRANT")
    print("-" * 80)

    client = QdrantClient(
        path=str(QDRANT_PATH)
    )

    print("Qdrant connected successfully.")

    # ========================================================
    # RETRIEVAL
    # ========================================================

    print()
    print("-" * 80)
    print("RUNNING RETRIEVAL")
    print("-" * 80)

    retrieval_output = run_retrieval(
        client=client,
        original_query=TEST_QUERY,
        top_k_search=TOP_K_SEARCH,
        top_k_final=TOP_K_FINAL,
    )

    results = retrieval_output["results"]
    entities = retrieval_output["entities"]

    print("CVEs detected:", entities["cves"])
    print("Final results:", len(results))

    # ========================================================
    # DISPLAY RETRIEVED SOURCES
    # ========================================================

    print()
    print("-" * 80)
    print("RETRIEVED RESULTS")
    print("-" * 80)

    for index, result in enumerate(results, start=1):

        payload = result.get("payload", {})

        source = result.get(
            "source",
            "unknown"
        )

        similarity = result.get(
            "similarity"
        )

        score = result.get(
            "final_score"
        )

        print()
        print(f"[{index}] Source: {source}")
        print(f"    ID: {result.get('id')}")
        print(f"    Similarity: {similarity}")
        print(f"    Rerank Score: {score}")
        print(
            f"    Exact CVE Match: "
            f"{result.get('cve_match')}"
        )

        if source == "plugins_vulnerabilities":

            print(
                f"    Script Name: "
                f"{payload.get('script_name', 'N/A')}"
            )

            print(
                f"    CVE: "
                f"{payload.get('cves', 'N/A')}"
            )

            print(
                f"    Risk: "
                f"{payload.get('risk_factor', 'N/A')}"
            )

        elif source == "qualys_vulnerabilities":

            print(
                f"    QID: "
                f"{payload.get('qid', 'N/A')}"
            )

            print(
                f"    Title: "
                f"{payload.get('title', 'N/A')}"
            )

            print(
                f"    CVE: "
                f"{payload.get('cve_list', 'N/A')}"
            )

    # ========================================================
    # BUILD LLM CONTEXT
    # ========================================================

    print()
    print("-" * 80)
    print("BUILDING LLM CONTEXT")
    print("-" * 80)

    context = build_context(
        results=results,
        max_results=TOP_K_FINAL,
    )

    print(
        f"Context created successfully "
        f"({len(context)} characters)."
    )

    # ========================================================
    # BUILD PROMPT
    # ========================================================

    print()
    print("-" * 80)
    print("BUILDING GEMINI PROMPT")
    print("-" * 80)

    prompt = build_prompt(
        user_query=TEST_QUERY,
        context=context,
    )

    print(
        f"Prompt created successfully "
        f"({len(prompt)} characters)."
    )

    # ========================================================
    # GEMINI
    # ========================================================

    print()
    print("-" * 80)
    print("CALLING GEMINI")
    print("-" * 80)

    answer = generate_answer(
        prompt=prompt
    )

    # ========================================================
    # FINAL ANSWER
    # ========================================================

    print()
    print("=" * 80)
    print("GEMINI FINAL ANSWER")
    print("=" * 80)

    print()
    print(answer)

    print()
    print("=" * 80)
    print("END-TO-END RAG TEST SUCCESSFUL")
    print("=" * 80)


if __name__ == "__main__":
    main()