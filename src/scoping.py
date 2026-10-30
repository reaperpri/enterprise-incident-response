import json
from pathlib import Path
from datetime import datetime, timezone

from src.triage import load_evidence, generate_triage_report


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_FILE = PROJECT_ROOT / "outputs" / "incident_scope_report.json"


SUSPICIOUS_EVENT_TYPES = {
    "LOGIN_FAILURE",
    "LOGIN_SUCCESS",
    "PROCESS_EXECUTION",
    "DISCOVERY",
    "FILE_DOWNLOAD",
    "LOG_DELETION"
}


def identify_suspicious_events(events):
    """Identify records that require further investigation."""

    return [
        event for event in events
        if event["event_type"] in SUSPICIOUS_EVENT_TYPES
    ]


def identify_affected_assets(events):
    """Identify systems appearing in the available evidence."""

    return sorted({
        event["host"]
        for event in events
    })


def identify_accounts(events):
    """Identify observed account names."""

    return sorted({
        event["username"]
        for event in events
    })


def identify_critical_findings(events):
    """Extract important observations for the incident commander."""

    findings = []

    for event in events:

        if event["event_type"] == "LOGIN_SUCCESS":
            findings.append(
                f"{event['timestamp']}: Successful login "
                f"following repeated authentication failures."
            )

        elif event["event_type"] == "FILE_DOWNLOAD":
            findings.append(
                f"{event['timestamp']}: Multiple finance file "
                f"downloads reported on {event['host']}."
            )

        elif event["event_type"] == "LOG_DELETION":
            findings.append(
                f"{event['timestamp']}: Security event log "
                f"deletion reported on {event['host']}."
            )

        elif event["event_type"] == "PROCESS_EXECUTION":
            findings.append(
                f"{event['timestamp']}: PowerShell execution "
                f"reported on {event['host']}."
            )

    return findings


def identify_investigation_gaps(events):
    """Identify questions that cannot yet be answered."""

    gaps = [
        "The identity of the person operating the account is unverified.",
        "The legitimacy of the successful authentication is unconfirmed.",
        "The destination of downloaded finance files is unknown.",
        "The actual contents and volume of downloaded files are unverified.",
        "The reason and actor behind security log deletion are unknown.",
        "The source of the activity has not been independently attributed.",
        "Additional authentication and network telemetry is required."
    ]

    observed_accounts = {
        event["username"] for event in events
    }

    if "unknown" in observed_accounts:
        gaps.append(
            "At least one event has an unknown account attribution."
        )

    return gaps


def build_scope_report(events):

    if not events:
        raise ValueError("No evidence events available for scoping.")

    triage = generate_triage_report(events)

    timestamps = sorted(
        datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )
        for event in events
    )

    suspicious = identify_suspicious_events(events)

    report = {
        "case_id": "CASE-DAY5-001",
        "report_generated_utc": datetime.now(
            timezone.utc
        ).isoformat(),

        "incident_overview": {
            "total_events_reviewed": len(events),
            "suspicious_events": len(suspicious),
            "incident_severity": triage["incident_severity"],
            "impact": triage["impact"],
            "recoverability": triage["recoverability"]
        },

        "investigation_window": {
            "first_observed_event": timestamps[0].isoformat(),
            "last_observed_event": timestamps[-1].isoformat()
        },

        "assets_observed": identify_affected_assets(events),

        "accounts_observed": identify_accounts(events),

        "critical_findings": identify_critical_findings(events),

        "investigation_gaps": identify_investigation_gaps(events),

        "scope_statement": (
            "The available synthetic evidence indicates suspicious "
            "authentication and subsequent endpoint and finance "
            "file-server activity. The investigation scope is limited "
            "to the two observed hosts and the records supplied. "
            "Additional evidence is required to establish the full "
            "extent, attribution and business impact."
        )
    }

    return report


def save_scope_report(report):

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(report, file, indent=4)

    return OUTPUT_FILE


def main():

    print("\n===== ENTERPRISE INCIDENT SCOPING =====")

    events = load_evidence()

    print(f"\nEvidence records reviewed: {len(events)}")

    report = build_scope_report(events)

    output = save_scope_report(report)

    print("\nINCIDENT OVERVIEW")

    print(
        "Severity:",
        report["incident_overview"]["incident_severity"]
    )

    print(
        "Suspicious events:",
        report["incident_overview"]["suspicious_events"]
    )

    print("\nASSETS OBSERVED")

    for asset in report["assets_observed"]:
        print("-", asset)

    print("\nACCOUNTS OBSERVED")

    for account in report["accounts_observed"]:
        print("-", account)

    print("\nCRITICAL FINDINGS")

    for finding in report["critical_findings"]:
        print("-", finding)

    print("\nINVESTIGATION GAPS")

    for gap in report["investigation_gaps"]:
        print("-", gap)

    print("\nScope report generated:", output)


if __name__ == "__main__":
    main()