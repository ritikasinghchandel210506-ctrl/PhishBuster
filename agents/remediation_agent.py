"""
Remediation Agent — builds the "Possible Attack Chain" visualization and the
"I Already Clicked" incident-response guidance. All advice here is
defensive only.
"""
from __future__ import annotations

ATTACK_CHAINS = {
    "Credential Harvesting": [
        "Email received", "Suspicious link clicked", "Fake login page",
        "Credentials entered", "Account compromise",
    ],
    "BEC / CEO Fraud": [
        "Spoofed/urgent email received", "Trust or authority exploited",
        "Employee pressured to act quickly", "Funds or data transferred",
        "Financial loss",
    ],
    "Financial Scam": [
        "Email received", "Fake invoice or refund claim", "Payment/bank details requested",
        "Victim submits financial information", "Financial loss",
    ],
    "Tech Support Scam": [
        "Fake virus/alert email received", "Victim calls fraudulent number",
        "Remote access requested", "Attacker gains device control", "Data theft or payment demanded",
    ],
    "Lottery / Prize Scam": [
        "Prize-winning email received", "Victim replies with interest",
        "Personal details or 'processing fee' requested", "Payment sent", "Financial loss, no prize received",
    ],
    "Delivery Scam": [
        "Fake delivery notification received", "Victim clicks tracking/fee link",
        "Fake payment/verification page", "Payment or card details entered", "Financial/data theft",
    ],
    "Other / Unknown": [
        "Email received", "Suspicious content or link present",
        "Potential victim interaction", "Possible compromise (type unclear)",
    ],
}

INCIDENT_SCENARIOS = {
    "opened_only": {
        "label": "I only opened the email",
        "actions": [
            "In most cases, simply opening a plain-text email is low risk.",
            "Do not click any links or open any attachments in the email.",
            "Mark the email as spam/phishing in your mail client if possible.",
            "If the email loaded remote images, treat your address as 'confirmed active' to the sender and expect more spam.",
            "Report the email to your IT/security team if this is a work account.",
        ],
    },
    "clicked_link": {
        "label": "I clicked the link",
        "actions": [
            "Do not enter any information if a login or form page opened — close the tab immediately.",
            "Run a reputable antivirus/anti-malware scan on your device as a precaution.",
            "Check your browser for any unexpected extensions or downloads and remove them.",
            "Change your email account password as a precaution, and enable multi-factor authentication (MFA).",
            "Monitor your accounts for unusual activity over the next few days.",
        ],
    },
    "downloaded_attachment": {
        "label": "I downloaded an attachment",
        "actions": [
            "Do NOT open/run the downloaded file.",
            "Delete the file, then empty your Recycle Bin/Trash.",
            "Run a full antivirus/anti-malware scan on your device immediately.",
            "Disconnect the device from the network if you already opened/ran the file and suspect infection.",
            "Notify your IT/security team immediately if this is a work device.",
        ],
    },
    "entered_credentials": {
        "label": "I entered my credentials",
        "actions": [
            "Change the password for the affected account immediately, from a different, trusted device if possible.",
            "Change the password on any other account where you reused the same password.",
            "Enable multi-factor authentication (MFA) on the affected account.",
            "Review recent account activity/login history for anything unfamiliar.",
            "Contact your IT/security team (for work accounts) so they can monitor for misuse.",
            "Sign out of all active sessions/devices for that account, if the option is available.",
        ],
    },
    "submitted_financial_info": {
        "label": "I submitted financial information",
        "actions": [
            "Contact your bank or card issuer immediately to report the incident and consider freezing/replacing the card.",
            "Monitor your bank/card statements closely for unauthorized transactions.",
            "Report the incident through your bank's official fraud-reporting process.",
            "Consider placing a fraud alert or credit freeze with a credit bureau if account numbers were exposed.",
            "File a report with your local cybercrime/consumer-protection authority if money was lost.",
            "Keep records (screenshots, emails) of the incident for any dispute process.",
        ],
    },
}


class RemediationAgent:
    name = "Remediation Agent"

    def get_attack_chain(self, attack_type: str) -> list:
        return ATTACK_CHAINS.get(attack_type, ATTACK_CHAINS["Other / Unknown"])

    def get_incident_response(self, scenario_key: str) -> dict:
        return INCIDENT_SCENARIOS.get(scenario_key, INCIDENT_SCENARIOS["opened_only"])

    def all_scenarios(self) -> dict:
        return INCIDENT_SCENARIOS
