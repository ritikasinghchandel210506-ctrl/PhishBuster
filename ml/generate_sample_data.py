"""
Generates a small SYNTHETIC dataset of legitimate / spam / phishing email
text for demo training purposes. All content here is fabricated for this
project — no real user data, no real malicious payloads, no working links.

Run: python ml/generate_sample_data.py
"""
from __future__ import annotations

import csv
import os
import random

random.seed(42)

LEGITIMATE_TEMPLATES = [
    "Hi {name}, attaching the {doc} we discussed in today's meeting. Let me know if you have questions.",
    "Hello team, the {doc} for this sprint is ready for review. Please add comments by Friday.",
    "Hi {name}, thanks for joining the call earlier. Here are the notes and next steps we agreed on.",
    "Reminder: our {event} is scheduled for next {day} at {time}. Calendar invite is attached.",
    "Hi {name}, your order #{order} has shipped and should arrive within 5-7 business days.",
    "Dear {name}, your monthly statement is now available in your account portal. No action is required.",
    "Hi {name}, following up on our conversation - I've shared the {doc} on the shared drive.",
    "Hello, this is a confirmation that your appointment with Dr. {name} is booked for {day}.",
    "Hi {name}, welcome to the team! Your onboarding schedule for this {day} is attached.",
    "Hi {name}, just checking in - do you have bandwidth to review the {doc} this week?",
    "Hello, your subscription renewal receipt for this month is attached for your records.",
    "Hi {name}, great presenting today. I've attached the slides from the {event} as promised.",
]

SPAM_TEMPLATES = [
    "Buy now and save 70% on all products! Limited stock available, shop today.",
    "Hot singles in your area want to meet you tonight! Click to see profiles.",
    "Lose 20 pounds in 2 weeks with this one weird trick doctors don't want you to know!",
    "Earn $5000 a week working from home, no experience needed, sign up now!",
    "Get the best deals on watches, bags and electronics - up to 80% off today only!",
    "Congratulations, you qualify for a free trial of our premium supplement - order now!",
    "Refinance your mortgage today and save thousands - get a free quote in minutes!",
    "Your inbox subscription is expiring, renew now to keep receiving our newsletter deals.",
    "Amazing vacation packages starting at $99 - book your dream getaway now!",
    "Free sample of our new skincare line - just pay shipping, click here to claim.",
]

PHISHING_CREDENTIAL_TEMPLATES = [
    "Dear customer, we detected unusual sign-in activity on your account. Verify your identity immediately or your account will be suspended: click here to login and confirm your password.",
    "Your {brand} account has been locked due to suspicious activity. Please verify your account information within 24 hours to avoid permanent suspension.",
    "Security Alert: We could not verify your recent login. Confirm your identity now by entering your password and OTP code to restore access.",
    "Your mailbox storage is full and incoming mail will be rejected. Click here to verify your account and increase your quota immediately.",
    "Action required: your {brand} password will expire today. Sign in now to update your credentials and avoid losing access.",
]

PHISHING_FINANCIAL_TEMPLATES = [
    "Your recent payment could not be processed. Update your billing details immediately to avoid service interruption and additional penalty fees.",
    "We attempted to deliver your refund of $450 but your bank details need verification. Click the link to confirm your payment information.",
    "Invoice attached: payment is overdue. Please process the wire transfer within 24 hours to avoid legal action.",
    "Your tax refund of $820 is ready for release. Confirm your bank account details to claim your unclaimed funds today.",
]

PHISHING_BEC_TEMPLATES = [
    "Hi, are you at your desk? I need you to process an urgent wire transfer before the end of day, keep this confidential for now.",
    "This is urgent - change of bank account for our vendor payment. Please update the new payment instructions and process it today.",
    "I'm in a meeting and can't talk, can you handle this discreetly? I need you to purchase gift cards for a client and send the codes.",
]

PHISHING_TECH_SUPPORT_TEMPLATES = [
    "Microsoft Support: Your computer has a virus! Windows Defender Alert detected suspicious activity. Call this number immediately for remote access support.",
    "Your device is infected with 5 viruses. Your license has expired. Contact our technical support team now to remove the threat.",
]

PHISHING_PRIZE_TEMPLATES = [
    "Congratulations! You have won a lucky winner cash prize of $1,000,000 in our international lottery. Claim your prize now by replying with your details.",
    "You have been selected to receive a free gift worth $500. Click here to claim your prize before it expires.",
]

PHISHING_DELIVERY_TEMPLATES = [
    "Your package could not be delivered due to an incomplete address. Reschedule your delivery and pay a small customs fee to release your parcel.",
    "DHL: Your shipment is on hold at the local facility. Your parcel is waiting - confirm your address and pay the customs fee to continue delivery.",
]

NAMES = ["Alex", "Priya", "John", "Meera", "Sam", "Chen", "Fatima", "Diego", "Anna", "Raj"]
DOCS = ["report", "proposal", "budget sheet", "design doc", "slide deck", "project plan"]
EVENTS = ["team sync", "quarterly review", "product demo", "town hall", "planning session"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
BRANDS = ["PayPal", "Microsoft", "Amazon", "Apple", "Netflix", "Bank"]


def _fill(template: str) -> str:
    return template.format(
        name=random.choice(NAMES), doc=random.choice(DOCS), event=random.choice(EVENTS),
        day=random.choice(DAYS), time=random.choice(["10:00 AM", "2:30 PM", "4:00 PM"]),
        order=random.randint(10000, 99999), brand=random.choice(BRANDS),
    )


def generate(n_per_class: int = 200) -> list:
    rows = []
    for _ in range(n_per_class):
        rows.append((_fill(random.choice(LEGITIMATE_TEMPLATES)), "legitimate"))
    for _ in range(n_per_class):
        rows.append((_fill(random.choice(SPAM_TEMPLATES)), "spam"))

    phishing_pools = [
        PHISHING_CREDENTIAL_TEMPLATES, PHISHING_FINANCIAL_TEMPLATES, PHISHING_BEC_TEMPLATES,
        PHISHING_TECH_SUPPORT_TEMPLATES, PHISHING_PRIZE_TEMPLATES, PHISHING_DELIVERY_TEMPLATES,
    ]
    for _ in range(n_per_class):
        pool = random.choice(phishing_pools)
        rows.append((_fill(random.choice(pool)), "phishing"))

    random.shuffle(rows)
    return rows


def main():
    out_path = os.path.join(os.path.dirname(__file__), "..", "data", "sample_emails.csv")
    out_path = os.path.abspath(out_path)
    rows = generate(n_per_class=200)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} synthetic rows to {out_path}")


if __name__ == "__main__":
    main()
