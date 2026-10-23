import re
import html
import pandas as pd


MISSING_VALUES = {
    "",
    "nan",
    "NaN",
    "NAN",
    "none",
    "None",
    "NONE",
    "null",
    "NULL",
    "nil",
    "NIL",
    "n/a",
    "N/A",
    "NA",
    "na",
}


def is_missing_value(value):
    """Check whether a value should be treated as missing."""

    if pd.isna(value):
        return True

    value = str(value).strip()

    return value in MISSING_VALUES


def clean_text(value):
    """
    Clean general text while preserving meaningful content.
    Missing values are represented as N/A.
    """

    if is_missing_value(value):
        return "N/A"

    value = str(value)

    # Decode HTML entities
    value = html.unescape(value)

    # Remove HTML/XML tags
    value = re.sub(r"<[^>]+>", " ", value)

    # Remove null characters
    value = value.replace("\x00", " ")

    # Normalize whitespace
    value = value.replace("\r", " ")
    value = value.replace("\n", " ")
    value = value.replace("\t", " ")

    # Collapse repeated spaces
    value = re.sub(r"\s+", " ", value)

    value = value.strip()

    if not value:
        return "N/A"

    return value


def clean_identifier(value):
    """
    Clean identifier-like fields without changing their meaning.
    """

    if is_missing_value(value):
        return "N/A"

    value = str(value).strip()

    value = re.sub(r"\s+", " ", value)

    return value


def normalize_boolean(value):
    """
    Normalize common boolean representations.
    """

    if is_missing_value(value):
        return "N/A"

    value = str(value).strip().lower()

    if value in {"true", "yes", "y", "1"}:
        return "Yes"

    if value in {"false", "no", "n", "0"}:
        return "No"

    return value


def normalize_numeric(value):
    """
    Normalize numeric values while preserving missing values.
    """

    if is_missing_value(value):
        return "N/A"

    value = str(value).strip()

    return value


def normalize_list_text(value):
    """
    Clean fields containing lists, references, ports, etc.
    """

    if is_missing_value(value):
        return "N/A"

    value = str(value)

    value = html.unescape(value)

    value = value.replace("\r", " ")
    value = value.replace("\n", " ")
    value = value.replace("\t", " ")

    value = re.sub(r"\s+", " ", value)

    value = value.strip()

    if not value:
        return "N/A"

    return value