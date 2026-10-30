import csv
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_ROOT / "evidence" / "incident_evidence.csv"
OUTPUT_FILE = PROJECT_ROOT / "outputs" / "master_incident_chronology.csv"


# Analyst interpretations are separate from the original evidence.
EVENT_INTERPRETATIONS = {
    "LOGIN_FAILURE": "Repeated authentication failure observed.",
    "LOGIN_SUCCESS": "Successful authentication observed after failures.",
    "PROCESS_EXECUTION": "PowerShell execution requires investigation.",
    "DISCOVERY": "System or identity discovery activity observed.",
    "NETWORK_CONNECTION": "Connection to another enterprise host observed.",
    "FILE_ACCESS": "Access to a finance shared folder observed.",
    "FILE_DOWNLOAD": "Multiple finance file downloads reported.",
    "LOG_DELETION": "Security event log deletion reported.",
    "LOGOUT": "Logout event recorded; session termination requires confirmation."
}


def load_events():
    """Load original evidence without modifying its contents."""

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Evidence file not found: {INPUT_FILE}"
        )

    with INPUT_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        required_fields = {
            "event_id",
            "timestamp",
            "host",
            "username",
            "source_ip",
            "event_type",
            "severity",
            "description"
        }

        if not reader.fieldnames or not required_fields.issubset(
            reader.fieldnames
        ):
            raise ValueError("Evidence CSV is missing required columns.")

        return list(reader)


def parse_timestamp(timestamp):
    """Convert ISO timestamps into timezone-aware datetime objects."""

    parsed = datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )

    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone.")

    return parsed.astimezone(timezone.utc)


def build_chronology(events):
    """Sort evidence and construct the master incident chronology."""

    sorted_events = sorted(
        events,
        key=lambda event: parse_timestamp(event["timestamp"])
    )

    chronology = []

    for index, event in enumerate(sorted_events, start=1):

        analyst_note = EVENT_INTERPRETATIONS.get(
            event["event_type"],
            "Event requires manual investigation."
        )

        chronology.append({
            "sequence": index,
            "timestamp_utc": parse_timestamp(
                event["timestamp"]
            ).isoformat(),
            "event_id": event["event_id"],
            "host": event["host"],
            "username": event["username"],
            "source_ip": event["source_ip"],
            "event_type": event["event_type"],
            "severity": event["severity"],
            "original_description": event["description"],
            "analyst_interpretation": analyst_note
        })

    return chronology


def export_chronology(chronology):
    """Export the chronology into a CSV deliverable."""

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    if not chronology:
        raise ValueError("No events available for chronology.")

    fieldnames = list(chronology[0].keys())

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(chronology)

    return OUTPUT_FILE


def display_chronology(chronology):
    """Display an investigator-friendly event sequence."""

    print("\n" + "=" * 100)
    print("              MASTER INCIDENT CHRONOLOGY")
    print("=" * 100)

    for event in chronology:

        print(
            f"\n[{event['sequence']:02d}] "
            f"{event['timestamp_utc']}"
        )

        print(
            f"Event ID : {event['event_id']} "
            f"| Type: {event['event_type']}"
        )

        print(
            f"Host     : {event['host']} "
            f"| Account: {event['username']}"
        )

        print(
            f"Severity : {event['severity']} "
            f"| Source IP: {event['source_ip']}"
        )

        print(
            f"Evidence : {event['original_description']}"
        )

        print(
            f"Analysis : {event['analyst_interpretation']}"
        )

        print("-" * 100)


def main():

    print("\n[+] Loading incident evidence...")

    events = load_events()

    print(f"[+] Records loaded: {len(events)}")

    print("[+] Reconstructing chronological sequence...")

    chronology = build_chronology(events)

    display_chronology(chronology)

    output = export_chronology(chronology)

    print("\n[+] CHRONOLOGY GENERATION COMPLETE")
    print(f"[+] Events processed: {len(chronology)}")
    print(f"[+] Output saved: {output}")


if __name__ == "__main__":
    main()