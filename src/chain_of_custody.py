import csv
import hashlib
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent

EVIDENCE_DIR = PROJECT_ROOT / "evidence"
CUSTODY_FILE = PROJECT_ROOT / "outputs" / "chain_of_custody.csv"
CUSTODY_HASH_FILE = PROJECT_ROOT / "outputs" / "chain_of_custody.sha256"


def calculate_sha256(file_path):
    """
    Calculate the SHA-256 hash of an evidence file.

    Read the file in chunks to avoid loading large files
    completely into memory.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(4096)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def custody_log_is_intact():
    """Check the custody log against its separately stored checksum."""

    if not CUSTODY_FILE.is_file() or not CUSTODY_HASH_FILE.is_file():
        return False

    expected_hash = CUSTODY_HASH_FILE.read_text(encoding="utf-8").strip()
    return bool(expected_hash) and calculate_sha256(CUSTODY_FILE) == expected_hash


def load_registered_record(evidence_id, filename):
    """Return the latest custody record for an evidence ID, if present."""

    if not CUSTODY_FILE.is_file() or CUSTODY_FILE.stat().st_size == 0:
        return None

    existing_record = None

    with CUSTODY_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for record in reader:
            if record.get("evidence_id") != evidence_id:
                continue

            if record.get("filename") != filename:
                raise ValueError(
                    f"Evidence ID {evidence_id} is already registered "
                    f"for a different filename."
                )

            existing_record = record

    return existing_record


def collect_evidence(
    evidence_id,
    filename,
    source_system,
    collector,
    storage_location
):
    """
    Register an existing evidence file.

    This function does not acquire evidence from a live system.
    It registers a training artifact already present in the lab.
    """

    file_path = EVIDENCE_DIR / filename

    if not file_path.is_file():
        raise FileNotFoundError(
            f"Evidence file does not exist: {file_path}"
        )

    existing_record = load_registered_record(evidence_id, filename)

    if existing_record is not None:
        return existing_record

    evidence_hash = calculate_sha256(file_path)

    record = {
        "evidence_id": evidence_id,
        "filename": filename,
        "source_system": source_system,
        "collector": collector,
        "collection_time_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "sha256": evidence_hash,
        "storage_location": storage_location,
        "action": "INITIAL_COLLECTION",
        "handled_by": collector,
        "notes": "Evidence registered in training environment."
    }

    save_custody_record(record)

    return record


def save_custody_record(record):

    CUSTODY_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if (
        CUSTODY_FILE.exists() or CUSTODY_HASH_FILE.exists()
    ) and not custody_log_is_intact():
        raise ValueError(
            f"Custody log integrity check failed: {CUSTODY_FILE}"
        )

    file_exists = CUSTODY_FILE.is_file() and CUSTODY_FILE.stat().st_size > 0

    with CUSTODY_FILE.open(
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=list(record.keys())
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(record)

    CUSTODY_HASH_FILE.write_text(
        calculate_sha256(CUSTODY_FILE) + "\n",
        encoding="utf-8"
    )


def verify_evidence(filename, original_hash):

    file_path = EVIDENCE_DIR / filename

    if not file_path.is_file() or not custody_log_is_intact():
        return False

    current_hash = calculate_sha256(file_path)

    return current_hash == original_hash


def main():

    print("\n===== DIGITAL EVIDENCE REGISTRATION =====")

    try:

        record = collect_evidence(
            evidence_id="EVID-001",
            filename="incident_evidence.csv",
            source_system="SRV-FILE-02",
            collector="SOC-ANALYST-01",
            storage_location="FORENSIC-VAULT-01"
        )

        print("\nEvidence registered successfully.")

        print(f"Evidence ID: {record['evidence_id']}")

        print(f"SHA-256: {record['sha256']}")

        print(
            f"Storage: {record['storage_location']}"
        )

        verified = verify_evidence(
            record["filename"],
            record["sha256"]
        )

        print(
            "\nIntegrity verification:",
            "PASSED" if verified else "FAILED"
        )

        print(f"Custody record: {CUSTODY_FILE}")

    except (FileNotFoundError, OSError, ValueError) as error:

        print(f"\nEvidence registration error: {error}")


if __name__ == "__main__":
    main()