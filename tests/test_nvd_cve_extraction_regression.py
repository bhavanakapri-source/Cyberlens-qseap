from nvd.nvd_service import _extract_cves_from_payload


def test_cve_found_inside_qualys_diagnosis():
    record = {
        "payload": {
            "QID": "12350",
            "TITLE": (
                "Pandora FMS Cross Site Scripting Vulnerability"
            ),
            "DIAGNOSIS": (
                "Affected versions. CVE-2020-11749. "
                "Update to release 747."
            ),
        }
    }

    result = _extract_cves_from_payload(
        record,
        "What is QID 12350?",
    )

    assert "CVE-2020-11749" in result


def test_cve_found_in_raw_retrieved_text():
    record = (
        "QID 12350 | Pandora FMS | "
        "Reference: CVE-2020-11749"
    )

    result = _extract_cves_from_payload(
        record,
        "What is QID 12350?",
    )

    assert result == ["CVE-2020-11749"]


def test_multiple_cves_are_unique_and_uppercase():
    record = (
        "CVE-2020-11749, cve-2020-11749, "
        "CVE-2021-12345"
    )

    result = _extract_cves_from_payload(record)

    assert result == [
        "CVE-2020-11749",
        "CVE-2021-12345",
    ]


def test_cve_found_in_nested_payload():
    record = {
        "payload": {
            "QID": "12350",
            "references": [
                {
                    "url": (
                        "https://example.com/"
                        "CVE-2020-11749"
                    )
                }
            ],
        }
    }

    result = _extract_cves_from_payload(record)

    assert "CVE-2020-11749" in result