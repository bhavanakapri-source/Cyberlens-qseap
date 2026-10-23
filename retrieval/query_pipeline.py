from .query_processor import preprocess_query
from .cve_extractor import extract_entities
from .query_embedder import embed_query
from .hybrid_search import hybrid_search
from .result_merger import merge_results
from .reranker import rerank_results


def run_retrieval(
    client,
    original_query,
    top_k_search=100,
    top_k_final=10
):

    # --------------------------------------------------
    # 1. Preprocess complete user query
    # --------------------------------------------------

    processed_query = preprocess_query(
        original_query
    )

    # --------------------------------------------------
    # 2. Extract useful structured information
    # --------------------------------------------------

    entities = extract_entities(
        processed_query
    )

    cves = entities["cves"]
    qids = entities["qids"]
    plugin_ids = entities["plugin_ids"]
    bids = entities["bids"]

    # --------------------------------------------------
    # 3. Embed COMPLETE user query
    # --------------------------------------------------

    query_vector = embed_query(
        processed_query
    )

    # --------------------------------------------------
    # 4. Hybrid retrieval
    # --------------------------------------------------

    hybrid_results = hybrid_search(
        client=client,
        query_vector=query_vector,
        cves=cves,
        qids=qids,
        plugin_ids=plugin_ids,
        bids=bids,
        top_k=top_k_search,
    )

    # --------------------------------------------------
    # 5. Merge semantic + exact identifier candidates
    # --------------------------------------------------

    merged = merge_results(
    cve_results=hybrid_results["cve_results"],
    semantic_results=hybrid_results["semantic_results"],
    qid_results=hybrid_results["qid_results"],
    plugin_results=hybrid_results["plugin_results"],
    bid_results=hybrid_results["bid_results"],
    )   
    # --------------------------------------------------
    # 6. Payload-aware multi-signal reranking
    # --------------------------------------------------

    final_results = rerank_results(
        results=merged,
        processed_query=processed_query,
        cves=cves,
        top_k=top_k_final,
    )

    # --------------------------------------------------
    # 7. Return complete retrieval result
    # --------------------------------------------------

    return {
        "original_query": original_query,
        "processed_query": processed_query,
        "entities": entities,
        "results": final_results,
    }