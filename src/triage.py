import csv
from pathlib import Path
from collections import Counter


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_ROOT / "evidence" / "incident_evidence.csv"


def load_evidence():
    """Load incident evidence from the CSV file."""

    with open(DATA_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)
        return list(reader)


def assess_impact(events):
    """
    Estimate potential incident impact from observed events.

    This is a teaching rule set, not an official NIST scoring formula.
    """

    event_types = [event["event_type"] for event in events]

    if "FILE_DOWNLOAD" in event_types and "LOG_DELETION" in event_types:
        return "High"

    if "FILE_DOWNLOAD" in event_types or "FILE_ACCESS" in event_types:
        return "Medium"

    return "Low"


def assess_recoverability(events):
    """
    Estimate recovery difficulty based on the available evidence.
    """

    event_types = [event["event_type"] for event in events]

    if "LOG_DELETION" in event_types:
        return "Difficult"

    if "FILE_DOWNLOAD" in event_types:
        return "Moderate"

    return "Easy"


def classify_severity(impact, recoverability):
    """
    Combine impact and recoverability into a training severity rating.
    """

    if impact == "High" and recoverability == "Difficult":
        return "CRITICAL"

    if impact == "High" or recoverability == "Difficult":
        return "HIGH"

    if impact == "Medium" or recoverability == "Moderate":
        return "MEDIUM"

    return "LOW"


def generate_triage_report(events):
    """Generate a summary of the incident."""

    event_counts = Counter(
        event["event_type"] for event in events
    )

    impact = assess_impact(events)
    recoverability = assess_recoverability(events)
    severity = classify_severity(impact, recoverability)

    report = {
        "total_events": len(events),
        "affected_hosts": sorted({
            event["host"] for event in events
        }),
        "accounts_observed": sorted({
            event["username"] for event in events
        }),
        "event_summary": dict(event_counts),
        "impact": impact,
        "recoverability": recoverability,
        "incident_severity": severity
    }

    return report


if __name__ == "__main__":

    evidence = load_evidence()

    report = generate_triage_report(evidence)

    print("\n===== INCIDENT TRIAGE REPORT =====")

    for key, value in report.items():
        print(f"{key}: {value}")