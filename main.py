import json
from pathlib import Path

from src.triage import load_evidence, generate_triage_report
from src.timeline import (
    load_events,
    build_chronology,
    export_chronology
)
from src.chain_of_custody import (
    collect_evidence,
    verify_evidence
)
from src.scoping import (
    build_scope_report,
    save_scope_report
)
from src.escalation import (
    create_escalation_register,
    save_register
)

PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "outputs"


def run_triage(events):

    print("\n[1/5] INCIDENT SEVERITY ASSESSMENT")

    report = generate_triage_report(events)

    print("Events reviewed:", report["total_events"])
    print("Impact:", report["impact"])
    print("Recoverability:", report["recoverability"])
    print("Severity:", report["incident_severity"])

    return report


def run_timeline():

    print("\n[2/5] MASTER INCIDENT CHRONOLOGY")

    events = load_events()

    chronology = build_chronology(events)

    output = export_chronology(chronology)

    print("Events reconstructed:", len(chronology))
    print("Timeline saved:", output)

    return chronology


def run_evidence_registration():

    print("\n[3/5] CHAIN OF CUSTODY")

    record = collect_evidence(
        evidence_id="EVID-001",
        filename="incident_evidence.csv",
        source_system="SRV-FILE-02",
        collector="SOC-ANALYST-01",
        storage_location="FORENSIC-VAULT-01"
    )

    verified = verify_evidence(
        record["filename"],
        record["sha256"]
    )

    if not verified:
        raise ValueError("Evidence or custody log integrity verification failed.")

    print("Evidence ID:", record["evidence_id"])
    print("SHA-256:", record["sha256"])
    print("Integrity verified:", verified)

    return record


def run_scoping(events):

    print("\n[4/5] INCIDENT SCOPING")

    report = build_scope_report(events)

    output = save_scope_report(report)

    print("Observed assets:", report["assets_observed"])
    print("Observed accounts:", report["accounts_observed"])
    print("Investigation gaps:", len(report["investigation_gaps"]))
    print("Scope report:", output)

    return report


def run_escalation():

    print("\n[5/5] CSIRT ESCALATION")

    register = create_escalation_register()

    output = save_register(register)

    print("Incident status:", register["incident_status"])
    print("CSIRT roles:", len(register["escalation_contacts"]))
    print("Pending actions:", len(register["next_actions"]))
    print("Escalation report:", output)

    return register


def main():

    print("=" * 65)
    print("       ENTERPRISE INCIDENT RESPONSE WORKBENCH")
    print("=" * 65)

    try:

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        print("\nLoading enterprise incident evidence...")

        events = load_evidence()

        print("Total records loaded:", len(events))

        triage = run_triage(events)

        chronology = run_timeline()

        custody = run_evidence_registration()

        scope = run_scoping(events)

        escalation = run_escalation()

        summary = {
            "case_id": "CASE-DAY5-001",
            "incident_severity": triage["incident_severity"],
            "events_reviewed": len(events),
            "timeline_events": len(chronology),
            "evidence_registered": custody["evidence_id"],
            "evidence_integrity_verified": verify_evidence(
                custody["filename"],
                custody["sha256"]
            ),
            "affected_assets_observed": scope["assets_observed"],
            "observed_accounts": scope["accounts_observed"],
            "csirt_roles": len(escalation["escalation_contacts"]),
            "investigation_status": "UNDER_INVESTIGATION"
        }

        summary_path = OUTPUT_DIR / "investigation_summary.json"

        with summary_path.open("w", encoding="utf-8") as file:
            json.dump(summary, file, indent=4)

        print("\n" + "=" * 65)
        print("       INCIDENT RESPONSE WORKFLOW COMPLETED")
        print("=" * 65)

        print("Case ID:", summary["case_id"])
        print("Severity:", summary["incident_severity"])
        print("Events reviewed:", summary["events_reviewed"])
        print("Evidence integrity:", summary["evidence_integrity_verified"])
        print("Investigation status:", summary["investigation_status"])

        print("\nAll deliverables are available in the outputs folder.")

    except (FileNotFoundError, ValueError, OSError) as error:

        print("\nWORKFLOW ERROR:", error)
        print("Review the evidence files and project structure.")


if __name__ == "__main__":
    main()