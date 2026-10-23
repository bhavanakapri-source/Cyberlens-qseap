def get_result_key(result):
    """
    Unique identity of a Qdrant record.
    """

    return (
        result["source"],
        result["id"],
    )


def merge_results(
    cve_results: list[dict],
    semantic_results: list[dict],
    qid_results: list[dict] | None = None,
    plugin_results: list[dict] | None = None,
    bid_results: list[dict] | None = None,
):
    """
    Merge exact identifier results and semantic results.

    Exact matches:
    - CVE
    - QID
    - Plugin ID
    - BID

    If the same record appears through multiple retrieval methods,
    combine the signals instead of creating duplicates.
    """

    merged = {}

    exact_results = (
        (cve_results or [])
        + (qid_results or [])
        + (plugin_results or [])
        + (bid_results or [])
    )

    # ---------------------------------------------------------
    # EXACT RESULTS
    # ---------------------------------------------------------

    for result in exact_results:

        key = get_result_key(result)

        if key not in merged:
            merged[key] = {
                **result,
                "identifier_match": result.get("identifier_match", False),
                "cve_match": result.get("cve_match", False),
                "similarity": result.get("similarity"),
            }

        else:
            merged[key]["identifier_match"] = (
                merged[key].get("identifier_match", False)
                or result.get("identifier_match", False)
            )

            merged[key]["cve_match"] = (
                merged[key].get("cve_match", False)
                or result.get("cve_match", False)
            )

    # ---------------------------------------------------------
    # SEMANTIC RESULTS
    # ---------------------------------------------------------

    for result in semantic_results or []:

        key = get_result_key(result)

        if key not in merged:

            merged[key] = {
                **result,
                "identifier_match": False,
                "cve_match": False,
            }

        else:

            # Same record was found by exact + semantic search
            merged[key]["similarity"] = result.get("similarity")

    return list(merged.values())