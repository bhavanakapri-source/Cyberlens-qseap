"""
Build grounded LLM context from reranked vulnerability results.

The context contains security-relevant information from BOTH:

    - Qualys
    - Plugins

The goal is to give Gemini enough evidence to produce:

    - accurate vulnerability explanations
    - severity information
    - exploitability information
    - affected products
    - diagnosis/details
    - remediation/fixes
"""

from typing import Any


# ============================================================
# HELPERS
# ============================================================

def clean_value(value: Any) -> str:
    """
    Convert payload values into readable text.
    """

    if value is None:
        return "N/A"

    if isinstance(value, list):
        if not value:
            return "N/A"

        return ", ".join(
            str(item)
            for item in value
            if item is not None
        )

    value = str(value).strip()

    if not value:
        return "N/A"

    return value


def add_field(
    lines: list[str],
    label: str,
    value: Any,
):
    """
    Add a field only when it contains useful information.
    """

    value = clean_value(value)

    if value != "N/A":
        lines.append(f"{label}: {value}")


# ============================================================
# QUALYS CONTEXT
# ============================================================

def build_qualys_context(
    result: dict,
    result_number: int,
) -> str:
    """
    Build complete security-relevant context for a Qualys result.

    IMPORTANT:
    Qualys payload fields use uppercase names in Qdrant.
    """

    payload = result.get("payload", {})

    lines = []

    lines.append(
        f"========== QUALYS RESULT {result_number} =========="
    )

    add_field(
        lines,
        "Retrieval Similarity",
        result.get("similarity"),
    )

    add_field(
        lines,
        "Exact CVE Match",
        result.get("cve_match"),
    )

    add_field(
        lines,
        "Identifier Match",
        result.get("identifier_match"),
    )

    # --------------------------------------------------------
    # Identification
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- IDENTIFICATION ---")

    add_field(
        lines,
        "QID",
        payload.get("QID"),
    )

    # cve_list is intentionally lowercase in Qdrant.
    add_field(
        lines,
        "CVE",
        payload.get("cve_list"),
    )

    add_field(
        lines,
        "Vulnerability Type",
        payload.get("VULN_TYPE"),
    )

    add_field(
        lines,
        "Title",
        payload.get("TITLE"),
    )

    add_field(
        lines,
        "Category",
        payload.get("CATEGORY"),
    )

    # --------------------------------------------------------
    # Vendor / Product
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- VENDOR / PRODUCT ---")

    add_field(
        lines,
        "Software Vendor",
        payload.get("SOFTWARE_VENDOR"),
    )

    add_field(
        lines,
        "Software Product",
        payload.get("SOFTWARE_PRODUCT"),
    )

    add_field(
        lines,
        "Supported Modules",
        payload.get("SUPPORTED_MODULES"),
    )

    # --------------------------------------------------------
    # Severity / Status
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- SEVERITY / STATUS ---")

    add_field(
        lines,
        "Severity Level",
        payload.get("SEVERITY_LEVEL"),
    )

    add_field(
        lines,
        "Patchable",
        payload.get("PATCHABLE"),
    )

    add_field(
        lines,
        "PCI Flag",
        payload.get("PCI_FLAG"),
    )

    add_field(
        lines,
        "Discovery Remote",
        payload.get("DISCOVERY_REMOTE"),
    )

    add_field(
        lines,
        "Disabled",
        payload.get("IS_DISABLED"),
    )

    # --------------------------------------------------------
    # Diagnosis
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- DIAGNOSIS / VULNERABILITY DETAILS ---")

    add_field(
        lines,
        "Diagnosis",
        payload.get("DIAGNOSIS"),
    )

    # --------------------------------------------------------
    # Dates
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- DATES ---")

    add_field(
        lines,
        "Published",
        payload.get("PUBLISHED_DATETIME"),
    )

    add_field(
        lines,
        "Last Service Modification",
        payload.get("LAST_SERVICE_MODIFICATION_DATETIME"),
    )

    return "\n".join(lines)


# ============================================================
# PLUGIN CONTEXT
# ============================================================

def build_plugin_context(
    result: dict,
    result_number: int,
) -> str:
    """
    Build complete security-relevant context for a Plugin result.
    """

    payload = result.get("payload", {})

    lines = []

    lines.append(
        f"========== PLUGIN RESULT {result_number} =========="
    )

    add_field(
        lines,
        "Retrieval Similarity",
        result.get("similarity"),
    )

    add_field(
        lines,
        "Exact CVE Match",
        result.get("cve_match"),
    )

    add_field(
        lines,
        "Identifier Match",
        result.get("identifier_match"),
    )

    # --------------------------------------------------------
    # Identification
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- IDENTIFICATION ---")

    add_field(
        lines,
        "Script ID",
        payload.get("script_id"),
    )

    add_field(
        lines,
        "Script Name",
        payload.get("script_name"),
    )

    add_field(
        lines,
        "Script Family",
        payload.get("script_family"),
    )

    add_field(
        lines,
        "Filename",
        payload.get("filename"),
    )

    add_field(
        lines,
        "CVE",
        payload.get("cves"),
    )

    add_field(
        lines,
        "BIDs",
        payload.get("bids"),
    )

    add_field(
        lines,
        "Cross References",
        payload.get("xrefs"),
    )

    # --------------------------------------------------------
    # Vulnerability Details
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- VULNERABILITY DETAILS ---")

    add_field(
        lines,
        "Description",
        payload.get("description"),
    )

    add_field(
        lines,
        "Synopsis",
        payload.get("synopsis"),
    )

    add_field(
        lines,
        "Potential Vulnerability",
        payload.get("potential_vulnerability"),
    )

    add_field(
        lines,
        "See Also",
        payload.get("see_also"),
    )

    # --------------------------------------------------------
    # Risk / Severity
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- RISK / SEVERITY ---")

    add_field(
        lines,
        "Risk Factor",
        payload.get("risk_factor"),
    )

    add_field(
        lines,
        "CVSS Base Score",
        payload.get("cvss_base_score"),
    )

    add_field(
        lines,
        "CVSS Vector",
        payload.get("cvss_vector"),
    )

    add_field(
        lines,
        "CVSS Temporal Score",
        payload.get("cvss_temporal_score"),
    )

    add_field(
        lines,
        "CVSS Temporal Vector",
        payload.get("cvss_temporal_vector"),
    )

    add_field(
        lines,
        "VPR Score",
        payload.get("vpr_score"),
    )

    add_field(
        lines,
        "EPSS Score",
        payload.get("epss_score"),
    )

    # --------------------------------------------------------
    # Exploitability
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- EXPLOITABILITY ---")

    add_field(
        lines,
        "Exploit Available",
        payload.get("exploit_available"),
    )

    add_field(
        lines,
        "Exploitability Ease",
        payload.get("exploitability_ease"),
    )

    add_field(
        lines,
        "Exploit Code Maturity",
        payload.get("exploit_code_maturity"),
    )

    # --------------------------------------------------------
    # Remediation
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- REMEDIATION ---")

    add_field(
        lines,
        "Solution",
        payload.get("solution"),
    )

    # --------------------------------------------------------
    # Product / Coverage
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- PRODUCT / COVERAGE ---")

    add_field(
        lines,
        "Product Coverage",
        payload.get("product_coverage"),
    )

    add_field(
        lines,
        "Plugin Type",
        payload.get("plugin_type"),
    )

    # --------------------------------------------------------
    # Dependencies / Conditions
    # --------------------------------------------------------

    lines.append("")
    lines.append("--- DETECTION / CONDITIONS ---")

    add_field(
        lines,
        "Dependencies",
        payload.get("dependencies"),
    )

    add_field(
        lines,
        "Required Ports",
        payload.get("required_ports"),
    )

    add_field(
        lines,
        "Required UDP Ports",
        payload.get("required_udp_ports"),
    )

    return "\n".join(lines)


# ============================================================
# MAIN CONTEXT BUILDER
# ============================================================

def build_context(
    results: list[dict],
    max_results: int = 10,
) -> str:
    """
    Build the final context that will be sent to the LLM.

    Results may come from:

        - plugins_vulnerabilities
        - qualys_vulnerabilities

    Each result retains its source so Gemini can distinguish
    Qualys evidence from Plugin evidence.
    """

    if not results:
        return (
            "No vulnerability records were retrieved "
            "from the knowledge base."
        )

    context_sections = []

    selected_results = results[:max_results]

    for index, result in enumerate(
        selected_results,
        start=1,
    ):

        source = result.get(
            "source",
            "",
        ).lower()

        if source == "qualys_vulnerabilities":

            section = build_qualys_context(
                result=result,
                result_number=index,
            )

        elif source == "plugins_vulnerabilities":

            section = build_plugin_context(
                result=result,
                result_number=index,
            )

        else:

            # Fallback for unexpected sources.
            section = (
                f"========== RESULT {index} ==========\n"
                f"Source: {result.get('source', 'Unknown')}\n"
                f"Payload: {result.get('payload', {})}"
            )

        context_sections.append(section)

    return "\n\n".join(context_sections)


# ============================================================
# SIMPLE DEBUG TEST
# ============================================================

if __name__ == "__main__":

    sample_results = [
        {
            "id": 94709,
            "source": "plugins_vulnerabilities",
            "similarity": 0.574,
            "cve_match": False,
            "identifier_match": False,
            "payload": {
                "script_id": 94709,
                "script_name": (
                    "Windows Server 2008 "
                    "Critical RCE Vulnerabilities"
                ),
                "cves": "CVE-EXAMPLE-1234",
                "risk_factor": "Critical",
                "exploit_available": "Yes",
                "solution": (
                    "Ensure the appropriate "
                    "patches have been applied."
                ),
                "description": (
                    "Example vulnerability description."
                ),
                "cvss_base_score": "9.8",
            },
        },
        {
            "id": 12345,
            "source": "qualys_vulnerabilities",
            "similarity": 0.55,
            "cve_match": False,
            "identifier_match": False,
            "payload": {
                "QID": 12345,
                "cve_list": "CVE-EXAMPLE-1234",
                "TITLE": "Example Windows Vulnerability",
                "SEVERITY_LEVEL": "5",
                "SOFTWARE_VENDOR": "Microsoft",
                "SOFTWARE_PRODUCT": "Windows Server",
                "PATCHABLE": "Yes",
                "DIAGNOSIS": (
                    "The vulnerability can be "
                    "addressed using the vendor patch."
                ),
            },
        },
    ]

    context = build_context(
        results=sample_results,
        max_results=10,
    )

    print("=" * 80)
    print("GENERATED LLM CONTEXT")
    print("=" * 80)
    print(context)
    print("=" * 80)