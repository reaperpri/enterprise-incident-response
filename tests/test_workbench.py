import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src import chain_of_custody
from src.scoping import build_scope_report
from src.timeline import build_chronology, load_events
from src.triage import generate_triage_report, load_evidence


class WorkbenchTests(unittest.TestCase):

    def test_sample_evidence_triage(self):
        events = load_evidence()

        report = generate_triage_report(events)

        self.assertEqual(report["total_events"], 14)
        self.assertEqual(report["incident_severity"], "CRITICAL")

    def test_chronology_is_ordered_and_preserves_uncertain_logout(self):
        chronology = build_chronology(load_events())

        self.assertEqual(len(chronology), 14)
        self.assertEqual(chronology[0]["event_id"], "E001")
        self.assertEqual(chronology[-1]["event_id"], "E014")
        self.assertEqual(
            chronology[-1]["analyst_interpretation"],
            "Logout event recorded; session termination requires confirmation."
        )

    def test_scoping_rejects_empty_evidence(self):
        with self.assertRaisesRegex(ValueError, "No evidence events"):
            build_scope_report([])

    def test_custody_detects_log_modification(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            evidence_dir = root / "evidence"
            outputs_dir = root / "outputs"
            evidence_dir.mkdir()
            outputs_dir.mkdir()

            evidence_file = evidence_dir / "sample.csv"
            evidence_file.write_text("sample evidence\n", encoding="utf-8")

            with (
                patch.object(chain_of_custody, "EVIDENCE_DIR", evidence_dir),
                patch.object(
                    chain_of_custody,
                    "CUSTODY_FILE",
                    outputs_dir / "chain_of_custody.csv"
                ),
                patch.object(
                    chain_of_custody,
                    "CUSTODY_HASH_FILE",
                    outputs_dir / "chain_of_custody.sha256"
                )
            ):
                record = chain_of_custody.collect_evidence(
                    "TEST-001",
                    evidence_file.name,
                    "TEST-SYSTEM",
                    "TEST-ANALYST",
                    "TEST-VAULT"
                )

                self.assertTrue(
                    chain_of_custody.verify_evidence(
                        record["filename"],
                        record["sha256"]
                    )
                )

                with chain_of_custody.CUSTODY_FILE.open(
                    "a",
                    encoding="utf-8"
                ) as ledger:
                    ledger.write("# modification\n")

                self.assertFalse(
                    chain_of_custody.verify_evidence(
                        record["filename"],
                        record["sha256"]
                    )
                )

                with self.assertRaisesRegex(
                    ValueError,
                    "Custody log integrity check failed"
                ):
                    chain_of_custody.collect_evidence(
                        "TEST-002",
                        evidence_file.name,
                        "TEST-SYSTEM",
                        "TEST-ANALYST",
                        "TEST-VAULT"
                    )

    def test_existing_custody_log_without_checksum_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            evidence_dir = root / "evidence"
            outputs_dir = root / "outputs"
            evidence_dir.mkdir()
            outputs_dir.mkdir()

            evidence_file = evidence_dir / "sample.csv"
            evidence_file.write_text("sample evidence\n", encoding="utf-8")
            custody_file = outputs_dir / "chain_of_custody.csv"
            custody_file.write_text("unverified ledger\n", encoding="utf-8")

            with (
                patch.object(chain_of_custody, "EVIDENCE_DIR", evidence_dir),
                patch.object(chain_of_custody, "CUSTODY_FILE", custody_file),
                patch.object(
                    chain_of_custody,
                    "CUSTODY_HASH_FILE",
                    outputs_dir / "chain_of_custody.sha256"
                )
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "Custody log integrity check failed"
                ):
                    chain_of_custody.collect_evidence(
                        "TEST-003",
                        evidence_file.name,
                        "TEST-SYSTEM",
                        "TEST-ANALYST",
                        "TEST-VAULT"
                    )


if __name__ == "__main__":
    unittest.main()
