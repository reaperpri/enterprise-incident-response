import json
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_FILE = (
    PROJECT_ROOT / "outputs" / "csirt_escalation_register.json"
)


CSIRT_ROLES = [
    {
        "role": "SOC Analyst",
        "responsibility": "Validate alerts and preserve initial observations.",
        "priority": "Immediate",
        "notification": "Incident Commander"
    },
    {
        "role": "Incident Commander",
        "responsibility": "Coordinate incident response and decisions.",
        "priority": "Immediate",
        "notification": "CSIRT and Security Leadership"
    },
    {
        "role": "Digital Forensics Analyst",
        "responsibility": "Preserve and examine relevant evidence.",
        "priority": "Immediate",
        "notification": "Incident Commander"
    },
    {
        "role": "Identity Administrator",
        "responsibility": "Investigate suspicious account activity.",
        "priority": "High",
        "notification": "Incident Commander"
    },
    {
        "role": "Infrastructure Administrator",
        "responsibility": "Assess affected workstations and servers.",
        "priority": "High",
        "notification": "Incident Commander"
    },
    {
        "role": "Legal and Compliance",
        "responsibility": "Assess applicable legal and regulatory obligations.",
        "priority": "High",
        "notification": "Security Leadership"
    },
    {
        "role": "Business Owner",
        "responsibility": "Assess operational and financial impact.",
        "priority": "High",
        "notification": "Incident Commander"
    },
    {
        "role": "Communications Lead",
        "responsibility": "Coordinate authorised stakeholder updates.",
        "priority": "Medium",
        "notification": "Incident Commander"
    }
]


def create_escalation_register():

    return {
        "case_id": "CASE-DAY5-001",

        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),

        "incident_status": "UNDER_INVESTIGATION",

        "incident_severity": "CRITICAL",

        "incident_commander": "UNASSIGNED",

        "communication_policy": (
            "Share incident information only with authorised "
            "stakeholders on a need-to-know basis."
        ),

        "approval_requirements": [
            "Host isolation requires authorised approval.",
            "Account disabling requires authorised approval.",
            "Production service shutdown requires business and "
            "technical coordination.",
            "External notifications require legal and management review."
        ],

        "escalation_contacts": CSIRT_ROLES,

        "next_actions": [
            {
                "action": "Validate suspicious authentication",
                "owner": "SOC Analyst",
                "priority": "Immediate",
                "status": "PENDING"
            },
            {
                "action": "Preserve relevant security evidence",
                "owner": "Digital Forensics Analyst",
                "priority": "Immediate",
                "status": "PENDING"
            },
            {
                "action": "Investigate finance server access",
                "owner": "Infrastructure Administrator",
                "priority": "High",
                "status": "PENDING"
            },
            {
                "action": "Validate account ownership",
                "owner": "Identity Administrator",
                "priority": "High",
                "status": "PENDING"
            },
            {
                "action": "Assess business impact",
                "owner": "Business Owner",
                "priority": "High",
                "status": "PENDING"
            }
        ]
    }


def save_register(register):

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(register, file, indent=4)

    return OUTPUT_FILE


def display_register(register):

    print("\n===== CSIRT ESCALATION REGISTER =====")

    print("Case:", register["case_id"])

    print("Status:", register["incident_status"])

    print("Severity:", register["incident_severity"])

    print("\nCSIRT COMMUNICATION TREE")

    for member in register["escalation_contacts"]:

        print(f"\nRole: {member['role']}")

        print(f"Priority: {member['priority']}")

        print(f"Responsibility: {member['responsibility']}")

        print(f"Reports to / Notifies: {member['notification']}")

    print("\nRESPONSE ACTIONS")

    for action in register["next_actions"]:

        print(
            f"\n[{action['priority']}] {action['action']}"
        )

        print("Owner:", action["owner"])

        print("Status:", action["status"])


def main():

    register = create_escalation_register()

    display_register(register)

    output = save_register(register)

    print("\nEscalation register saved:", output)


if __name__ == "__main__":
    main()