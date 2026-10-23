import re


def preprocess_query(query: str) -> str:
    """
    Step 3:
    Clean and normalize the original user query.
    """

    if not query or not query.strip():
        raise ValueError("Query cannot be empty.")

    # Lowercase
    query = query.lower()

    # Normalize whitespace
    query = re.sub(r"\s+", " ", query).strip()

    # Keep useful security characters such as CVE hyphens
    query = re.sub(r"[^\w\s\-./:]", " ", query)

    # Normalize whitespace again
    query = re.sub(r"\s+", " ", query).strip()

    return query