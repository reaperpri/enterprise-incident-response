# Enterprise Incident Response Workbench

A Python training project that analyzes synthetic incident evidence and
generates incident-triage, timeline, chain-of-custody, scoping, and escalation
reports. It uses only the Python standard library.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Project layout

```text
.
├── evidence/
│   └── incident_evidence.csv
├── outputs/                 # Generated reports (ignored by Git)
├── src/
│   ├── chain_of_custody.py
│   ├── escalation.py
│   ├── scoping.py
│   ├── timeline.py
│   └── triage.py
├── tests/
│   └── test_workbench.py
├── main.py
└── README.md
```

## Run the workbench

From the project directory:

```bash
python main.py
```

The workflow reads `evidence/incident_evidence.csv`, prints the triage
assessment, and writes these generated files to `outputs/`:

- `master_incident_chronology.csv`
- `chain_of_custody.csv` and `chain_of_custody.sha256`
- `incident_scope_report.json`
- `csirt_escalation_register.json`
- `investigation_summary.json`

Run an individual module with, for example:

```bash
python -m src.triage
python -m src.timeline
python -m src.chain_of_custody
python -m src.scoping
python -m src.escalation
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## What the sample evidence describes

The sample contains 14 synthetic events, including repeated authentication
failures, a subsequent successful login, endpoint discovery, finance file
access and downloads, and reported security-log deletion. The training rules
currently classify the incident as **CRITICAL**.

## Limitations

- The evidence and response details are synthetic and for education only.
- Severity ratings are illustrative rules, not an official scoring standard.
- Observed activity does not by itself prove compromise or identify an actor.
- The project does not acquire evidence from live systems or perform
  containment/remediation actions.
- The custody CSV's SHA-256 sidecar detects changes only while the sidecar
  remains unchanged. Since both files are stored together, this is not
  tamper-proof forensic storage; production workflows should protect the
  baseline separately.
- CSIRT roles, contacts, and actions are examples and must be adapted and
  approved for a real organization.

No license is included. Choose an appropriate license before distributing the
project publicly.
