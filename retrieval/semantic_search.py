from qdrant_client import QdrantClient


QUALYS_COLLECTION = "qualys_vulnerabilities"
PLUGINS_COLLECTION = "plugins_vulnerabilities"


def semantic_search(
    client,
    collection_name,
    query_vector,
    limit=100
):
    """
    Semantic search using the complete user query embedding.

    Payload is returned together with every vector result so that
    payload-aware reranking can happen afterward.
    """

    response = client.query_points(
        collection_name=collection_name,
        query=query_vector,
        limit=limit,
        with_payload=True,
        with_vectors=False,
    )

    results = []

    for point in response.points:

        results.append({
            "id": point.id,
            "source": collection_name,
            "similarity": float(point.score),
            "cve_match": False,
            "payload": point.payload,
        })

    return results


def semantic_search_both_collections(
    client,
    query_vector,
    limit=100
):
    """
    Search both vulnerability collections using the
    same complete query embedding.
    """

    qualys_results = semantic_search(
        client,
        QUALYS_COLLECTION,
        query_vector,
        limit
    )

    plugins_results = semantic_search(
        client,
        PLUGINS_COLLECTION,
        query_vector,
        limit
    )

    return qualys_results + plugins_results