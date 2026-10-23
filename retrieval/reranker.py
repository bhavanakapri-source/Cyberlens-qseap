import re


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(value) -> str:
    """
    Convert any payload value into normalized lowercase text.

    Handles None, strings, lists, and other values safely.
    """

    if value is None:
        return ""

    if isinstance(value, list):
        value = " ".join(str(item) for item in value)

    return str(value).lower().strip()


# ============================================================
# QUERY TERM EXTRACTION
# ============================================================

def get_query_terms(query: str) -> set[str]:
    """
    Extract useful words from the processed query.
    """

    stopwords = {
        "how",
        "can",
        "i",
        "we",
        "the",
        "a",
        "an",
        "is",
        "are",
        "to",
        "of",
        "in",
        "on",
        "for",
        "which",
        "what",
        "with",
        "and",
        "or",
        "do",
        "does",
        "it",
        "this",
        "that",
        "be",
        "my",
        "me",
        "most",
        "need",
        "immediate",
    }

    words = re.findall(r"\b[a-z0-9._-]+\b", query.lower())

    return {
        word
        for word in words
        if word not in stopwords and len(word) > 2
    }


# ============================================================
# QUERY INTENT
# ============================================================

def detect_query_intent(query: str) -> dict:
    """
    Detect important concepts explicitly mentioned by the user.
    """

    query_lower = query.lower()

    return {
        "windows": "windows" in query_lower,
        "linux": "linux" in query_lower,
        "microsoft": "microsoft" in query_lower,

        "critical": any(
            word in query_lower
            for word in ["critical", "most critical"]
        ),

        "high": "high" in query_lower,
        "medium": "medium" in query_lower,
        "low": "low" in query_lower,

        "exploit": any(
            word in query_lower
            for word in [
                "exploit",
                "exploitable",
                "exploited",
            ]
        ),

        "remediation": any(
            word in query_lower
            for word in [
                "fix",
                "solution",
                "patch",
                "remediation",
                "resolve",
                "mitigate",
            ]
        ),

        "severity": any(
            word in query_lower
            for word in [
                "severity",
                "critical",
                "high",
                "medium",
                "low",
            ]
        ),
    }


# ============================================================
# PRODUCT / PLATFORM RELEVANCE
# ============================================================

def calculate_product_relevance(
    payload: dict,
    intent: dict,
) -> float:
    """
    Calculate relevance based on explicitly mentioned
    vendors/products/platforms.

    IMPORTANT:
    Do NOT use generic description/synopsis fields for strong
    product matching.
    """

    score = 0.0

    product = normalize_text(payload.get("software_product"))
    vendor = normalize_text(payload.get("software_vendor"))
    title = normalize_text(payload.get("title"))
    script_name = normalize_text(payload.get("script_name"))

    # --------------------------------------------------------
    # WINDOWS
    # --------------------------------------------------------

    if intent["windows"]:

        if "windows" in product:
            score += 10.0

        elif "windows" in title:
            score += 8.0

        elif "windows" in script_name:
            score += 8.0

        elif "microsoft" in vendor:
            score += 6.0

    # --------------------------------------------------------
    # LINUX
    # --------------------------------------------------------

    if intent["linux"]:

        if "linux" in product:
            score += 10.0

        elif "linux" in title:
            score += 8.0

        elif "linux" in script_name:
            score += 8.0

        elif "linux" in vendor:
            score += 5.0

    # --------------------------------------------------------
    # MICROSOFT
    # --------------------------------------------------------

    if intent["microsoft"]:

        if "microsoft" in vendor:
            score += 10.0

        elif "microsoft" in product:
            score += 8.0

        elif "microsoft" in title:
            score += 7.0

        elif "microsoft" in script_name:
            score += 7.0

    return score


# ============================================================
# EXPLOITABILITY RELEVANCE
# ============================================================

def calculate_exploitability_relevance(
    payload: dict,
    intent: dict,
) -> float:

    if not intent["exploit"]:
        return 0.0

    score = 0.0

    exploit_available = normalize_text(
        payload.get("exploit_available")
    )

    exploitability_ease = normalize_text(
        payload.get("exploitability_ease")
    )

    potential_vulnerability = normalize_text(
        payload.get("potential_vulnerability")
    )

    exploit_code_maturity = normalize_text(
        payload.get("exploit_code_maturity")
    )

    # --------------------------------------------------------
    # Exploit Available
    # --------------------------------------------------------

    if exploit_available in {
        "yes",
        "true",
        "1",
        "available",
    }:
        score += 8.0

    # --------------------------------------------------------
    # Exploitability Ease
    # --------------------------------------------------------

    if exploitability_ease:

        if exploitability_ease in {
            "high",
            "easy",
            "functional",
            "proof of concept",
        }:
            score += 5.0

        elif exploitability_ease in {
            "medium",
            "moderate",
        }:
            score += 3.0

    # --------------------------------------------------------
    # Exploit Code Maturity
    # --------------------------------------------------------

    if exploit_code_maturity:

        if exploit_code_maturity in {
            "high",
            "functional",
            "highly functional",
        }:
            score += 4.0

        elif exploit_code_maturity in {
            "medium",
            "proof of concept",
            "poc",
        }:
            score += 2.0

    # --------------------------------------------------------
    # Potential Vulnerability
    # --------------------------------------------------------

    if potential_vulnerability:

        if any(
            word in potential_vulnerability
            for word in [
                "remote code execution",
                "code execution",
                "arbitrary code",
                "remote execution",
            ]
        ):
            score += 3.0

    return score


# ============================================================
# SEVERITY RELEVANCE
# ============================================================

def calculate_severity_relevance(
    payload: dict,
    intent: dict,
) -> float:

    if not intent["severity"]:
        return 0.0

    score = 0.0

    risk_factor = normalize_text(
        payload.get("risk_factor")
    )

    severity_level = normalize_text(
        payload.get("severity_level")
    )

    cvss_base_score = payload.get(
        "cvss_base_score"
    )

    cvss_temporal_score = payload.get(
        "cvss_temporal_score"
    )

    # --------------------------------------------------------
    # Text severity
    # --------------------------------------------------------

    severity_text = (
        risk_factor + " " + severity_level
    ).lower()

    # --------------------------------------------------------
    # User explicitly asks Critical
    # --------------------------------------------------------

    if intent["critical"]:

        if "critical" in severity_text:
            score += 12.0

        elif "high" in severity_text:
            score += 7.0

        elif "medium" in severity_text:
            score += 3.0

    # --------------------------------------------------------
    # User explicitly asks High
    # --------------------------------------------------------

    elif intent["high"]:

        if "high" in severity_text:
            score += 10.0

        elif "critical" in severity_text:
            score += 10.0

        elif "medium" in severity_text:
            score += 3.0

    # --------------------------------------------------------
    # User explicitly asks Medium
    # --------------------------------------------------------

    elif intent["medium"]:

        if "medium" in severity_text:
            score += 10.0

    # --------------------------------------------------------
    # User explicitly asks Low
    # --------------------------------------------------------

    elif intent["low"]:

        if "low" in severity_text:
            score += 10.0

    # --------------------------------------------------------
    # CVSS support
    # --------------------------------------------------------

    try:

        if cvss_base_score not in [None, "", "N/A"]:

            cvss = float(cvss_base_score)

            if intent["critical"] and cvss >= 9.0:
                score += 5.0

            elif intent["high"] and cvss >= 7.0:
                score += 4.0

    except (ValueError, TypeError):
        pass

    try:

        if cvss_temporal_score not in [None, "", "N/A"]:

            temporal = float(cvss_temporal_score)

            if intent["critical"] and temporal >= 9.0:
                score += 3.0

    except (ValueError, TypeError):
        pass

    return score


# ============================================================
# REMEDIATION RELEVANCE
# ============================================================

def calculate_remediation_relevance(
    payload: dict,
    intent: dict,
) -> float:

    if not intent["remediation"]:
        return 0.0

    score = 0.0

    solution = normalize_text(
        payload.get("solution")
    )

    diagnosis = normalize_text(
        payload.get("diagnosis")
    )

    patchable = normalize_text(
        payload.get("patchable")
    )

    # --------------------------------------------------------
    # Solution available
    # --------------------------------------------------------

    if solution and solution not in {
        "n/a",
        "na",
        "none",
        "null",
    }:
        score += 7.0

    # --------------------------------------------------------
    # Diagnosis available
    # --------------------------------------------------------

    if diagnosis and diagnosis not in {
        "n/a",
        "na",
        "none",
        "null",
    }:
        score += 2.0

    # --------------------------------------------------------
    # Patchable
    # --------------------------------------------------------

    if patchable in {
        "yes",
        "true",
        "1",
    }:
        score += 3.0

    return score


# ============================================================
# KEYWORD RELEVANCE
# ============================================================

def calculate_keyword_relevance(
    payload: dict,
    query_terms: set[str],
) -> float:

    if not query_terms:
        return 0.0

    fields = [
        payload.get("title"),
        payload.get("script_name"),
        payload.get("script_family"),
        payload.get("software_product"),
        payload.get("software_vendor"),
        payload.get("vuln_type"),
        payload.get("category"),
        payload.get("synopsis"),
    ]

    combined_text = " ".join(
        normalize_text(field)
        for field in fields
        if field
    )

    matched_terms = sum(
        1
        for term in query_terms
        if term in combined_text
    )

    # Keep this bounded so keyword matching cannot
    # overpower semantic relevance.
    return min(matched_terms * 2.0, 10.0)


# ============================================================
# CVE RELEVANCE
# ============================================================

def calculate_cve_match(
    result: dict,
    cves: list[str],
) -> float:

    if not cves:
        return 0.0

    # Exact CVE retrieval result.
    if result.get("cve_match"):
        return 100.0

    payload = result.get("payload", {})

    cve_text = normalize_text(
        payload.get("cves")
    )

    for cve in cves:

        if cve.lower() in cve_text:
            return 100.0

    return 0.0


# ============================================================
# IDENTIFIER RELEVANCE
# ============================================================

def calculate_identifier_match(
    result: dict,
) -> float:
    """
    Give exact identifier retrieval results very high priority.

    This applies to:
    - QID
    - Plugin ID / script_id
    - BID
    """

    if result.get("identifier_match") is True:
        return 100.0

    return 0.0


# ============================================================
# FINAL SCORE
# ============================================================

def calculate_score(
    result: dict,
    processed_query: str,
    cves: list[str],
) -> float:

    payload = result.get(
        "payload",
        {}
    )

    similarity = result.get(
        "similarity"
    )

    if similarity is None:
        similarity = 0.0

    intent = detect_query_intent(
        processed_query
    )

    query_terms = get_query_terms(
        processed_query
    )

    semantic_score = (
        float(similarity) * 10.0
    )

    product_score = (
        calculate_product_relevance(
            payload,
            intent,
        )
    )

    exploitability_score = (
        calculate_exploitability_relevance(
            payload,
            intent,
        )
    )

    severity_score = (
        calculate_severity_relevance(
            payload,
            intent,
        )
    )

    remediation_score = (
        calculate_remediation_relevance(
            payload,
            intent,
        )
    )

    keyword_score = (
        calculate_keyword_relevance(
            payload,
            query_terms,
        )
    )

    cve_score = (
        calculate_cve_match(
            result,
            cves,
        )
    )

    identifier_score = (
        calculate_identifier_match(
            result,
        )
    )

    # --------------------------------------------------------
    # Final weighted score
    # --------------------------------------------------------

    final_score = (
        semantic_score
        + product_score
        + exploitability_score
        + severity_score
        + remediation_score
        + keyword_score
        + cve_score
        + identifier_score
    )

    # Store score breakdown for debugging/testing.
    result["score_breakdown"] = {
        "semantic": round(
            semantic_score,
            4,
        ),

        "product": round(
            product_score,
            4,
        ),

        "exploitability": round(
            exploitability_score,
            4,
        ),

        "severity": round(
            severity_score,
            4,
        ),

        "remediation": round(
            remediation_score,
            4,
        ),

        "keyword": round(
            keyword_score,
            4,
        ),

        "cve": round(
            cve_score,
            4,
        ),

        "identifier": round(
            identifier_score,
            4,
        ),
    }

    return final_score


# ============================================================
# FINAL RERANKING
# ============================================================

def rerank_results(
    results,
    processed_query,
    cves,
    top_k=10,
):
    """
    Calculate final relevance score and return top results.

    Exact identifier matches receive priority for:
    - CVE
    - QID
    - Plugin ID
    - BID

    Semantic candidates remain available as supporting context.
    """

    for result in results:

        result["final_score"] = calculate_score(
            result=result,
            processed_query=processed_query,
            cves=cves,
        )

    # --------------------------------------------------------
    # Normal ranking
    # --------------------------------------------------------

    results.sort(
        key=lambda x: x["final_score"],
        reverse=True,
    )

    # --------------------------------------------------------
    # Exact identifier results get priority
    # --------------------------------------------------------

    exact_identifier_results = [
        result
        for result in results
        if (
            result.get("cve_match") is True
            or result.get("identifier_match") is True
        )
    ]

    other_results = [
        result
        for result in results
        if not (
            result.get("cve_match") is True
            or result.get("identifier_match") is True
        )
    ]

    results = (
        exact_identifier_results
        + other_results
    )

    return results[:top_k]