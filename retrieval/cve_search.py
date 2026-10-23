from qdrant_client import QdrantClient
from qdrant_client.models import (
    Filter,
    FieldCondition,
    MatchValue,
)


QUALYS_COLLECTION = "qualys_vulnerabilities"
PLUGINS_COLLECTION = "plugins_vulnerabilities"


def exact_payload_search(
    client: QdrantClient,
    collection_name: str,
    field_name: str,
    value,
    limit: int = 50,
):
    """
    Exact payload search in Qdrant.

    This is metadata/payload matching.
    It is NOT embedding similarity.
    """

    response = client.scroll(
        collection_name=collection_name,
        scroll_filter=Filter(
            must=[
                FieldCondition(
                    key=field_name,
                    match=MatchValue(value=value),
                )
            ]
        ),
        limit=limit,
        with_payload=True,
        with_vectors=False,
    )

    points, _ = response

    results = []

    for point in points:
        results.append({
            "id": point.id,
            "source": collection_name,
            "similarity": None,
            "cve_match": field_name == "cve_list",
            "identifier_match": field_name != "cve_list",
            "matched_field": field_name,
            "matched_value": value,
            "payload": point.payload,
        })

    return results


def exact_cve_search(
    client: QdrantClient,
    collection_name: str,
    cve: str,
    limit: int = 50,
):
    """
    Exact CVE search using the stored Qdrant payload.
    """

    return exact_payload_search(
        client=client,
        collection_name=collection_name,
        field_name="cve_list",
        value=cve.upper(),
        limit=limit,
    )


def exact_qid_search(
    client: QdrantClient,
    qid: int,
    limit: int = 50,
):
    """
    Exact Qualys QID search.
    """

    return exact_payload_search(
        client=client,
        collection_name=QUALYS_COLLECTION,
        field_name="QID",
        value=qid,
        limit=limit,
    )


def exact_plugin_id_search(
    client: QdrantClient,
    plugin_id: int,
    limit: int = 50,
):
    """
    Exact Plugin/Script ID search.
    """

    return exact_payload_search(
        client=client,
        collection_name=PLUGINS_COLLECTION,
        field_name="script_id",
        value=plugin_id,
        limit=limit,
    )


def exact_bid_search(
    client: QdrantClient,
    bid: int,
    limit: int = 50,
):
    """
    Exact BID search in the Plugins collection.

    BID is stored as a payload field named 'bids'.
    """

    return exact_payload_search(
        client=client,
        collection_name=PLUGINS_COLLECTION,
        field_name="bids",
        value=str(bid),
        limit=limit,
    )


def search_cve_in_both_collections(
    client: QdrantClient,
    cves: list[str],
    limit: int = 50,
):
    """
    Search extracted CVEs in BOTH collections.
    """

    results = []

    for cve in cves:

        results.extend(
            exact_cve_search(
                client=client,
                collection_name=QUALYS_COLLECTION,
                cve=cve,
                limit=limit,
            )
        )

        results.extend(
            exact_cve_search(
                client=client,
                collection_name=PLUGINS_COLLECTION,
                cve=cve,
                limit=limit,
            )
        )

    return results