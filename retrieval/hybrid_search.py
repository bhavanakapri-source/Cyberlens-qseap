from .cve_search import (
    search_cve_in_both_collections,
    exact_qid_search,
    exact_plugin_id_search,
    exact_bid_search,
)
from .semantic_search import semantic_search_both_collections


def hybrid_search(
    client,
    query_vector,
    cves,
    qids=None,
    plugin_ids=None,
    bids=None,
    top_k=100,
):
    """
    Hybrid retrieval:

    1. Exact identifier search
       - CVE  -> both collections
       - QID  -> Qualys
       - Plugin ID -> Plugins
       - BID  -> Plugins

    2. Semantic search
       - Always performed across both collections.

    Exact identifier matches are preserved separately so that
    the reranking stage can prioritize them.
    """

    cve_results = []
    qid_results = []
    plugin_results = []
    bid_results = []

    # --------------------------------------------------
    # Exact CVE search
    # --------------------------------------------------

    if cves:
        cve_results = search_cve_in_both_collections(
            client=client,
            cves=cves,
            limit=top_k,
        )

    # --------------------------------------------------
    # Exact Qualys QID search
    # --------------------------------------------------

    if qids:
        for qid in qids:
            qid_results.extend(
                exact_qid_search(
                    client=client,
                    qid=qid,
                    limit=top_k,
                )
            )

    # --------------------------------------------------
    # Exact Plugin / Script ID search
    # --------------------------------------------------

    if plugin_ids:
        for plugin_id in plugin_ids:
            plugin_results.extend(
                exact_plugin_id_search(
                    client=client,
                    plugin_id=plugin_id,
                    limit=top_k,
                )
            )

    # --------------------------------------------------
    # Exact BID search
    # --------------------------------------------------

    if bids:
        for bid in bids:
            bid_results.extend(
                exact_bid_search(
                    client=client,
                    bid=bid,
                    limit=top_k,
                )
            )

    # --------------------------------------------------
    # Semantic search
    # --------------------------------------------------

    semantic_results = semantic_search_both_collections(
        client=client,
        query_vector=query_vector,
        limit=top_k,
    )

    return {
        "cve_results": cve_results,
        "qid_results": qid_results,
        "plugin_results": plugin_results,
        "bid_results": bid_results,
        "semantic_results": semantic_results,
    }