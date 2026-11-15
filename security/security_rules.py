"""
Shared static rule tables used across security analyzers.
Kept in one place so the scoring methodology (docs/methodology.md) stays
consistent with the actual code.
"""

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "gq", "tk", "ml", "ga", "cf", "cam", "click",
    "quest", "work", "link", "rest", "loan", "win", "bid", "date", "review",
}

# Multi-label public-suffix-like endings we treat as a single TLD unit
# (small hand-maintained list; not a full public suffix list).
KNOWN_TWO_PART_SUFFIXES = {
    "co.uk", "co.in", "com.au", "co.jp", "com.br", "org.uk", "net.in",
    "ac.in", "gov.in", "co.nz", "com.cn",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "shorturl.at", "cutt.ly", "rb.gy", "tiny.cc",
}

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "mail.com", "protonmail.com", "zoho.com", "gmx.com",
    "yandex.com", "rediffmail.com",
}

LOGIN_KEYWORDS = {"login", "signin", "sign-in", "log-in", "logon", "account", "myaccount"}
CREDENTIAL_KEYWORDS = {"password", "passwd", "pwd", "credential", "otp", "2fa", "authenticate", "verify"}
VERIFICATION_KEYWORDS = {"verify", "verification", "confirm", "validate", "authenticate", "secure"}

DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".ps1",
    ".msi", ".msp", ".com", ".pif", ".hta", ".jar", ".wsf", ".wsh", ".cpl",
    ".gadget", ".reg",
}
MACRO_OFFICE_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".tar", ".gz", ".cab"}

URGENCY_PHRASES = [
    "act now", "immediate action", "urgent", "right away", "as soon as possible",
    "final notice", "last warning", "within 24 hours", "within 12 hours",
    "expires today", "immediately", "time sensitive", "asap",
]

THREAT_PHRASES = [
    "account will be suspended", "account has been locked", "legal action",
    "your account will be closed", "suspended", "terminated", "penalty",
    "deactivated", "permanently deleted", "your access will be revoked",
]

CREDENTIAL_REQUEST_PHRASES = [
    "enter your password", "confirm your password", "verify your account",
    "update your account information", "re-enter your credentials",
    "click here to login", "sign in to verify", "verify your identity",
    "confirm your identity", "enter your otp", "provide your one-time password",
]

FINANCIAL_REQUEST_PHRASES = [
    "wire transfer", "bank details", "gift card", "payment is overdue",
    "update your billing", "confirm your payment", "invoice attached",
    "transfer funds", "processing fee", "release your funds", "claim your prize",
    "tax refund", "unclaimed funds",
]

IMPERSONATION_PHRASES = [
    "official notification", "on behalf of", "customer support team",
    "security team", "billing department", "this is not a scam",
    "verified by", "authorized representative",
]

OTP_PASSWORD_PHRASES = ["one-time password", "otp code", "verification code", "security code", "pin number"]

ACCOUNT_SUSPENSION_PHRASES = [
    "account suspended", "account will be suspended", "unusual activity detected",
    "suspicious login attempt", "your account is at risk", "account limited",
]

PRIZE_PHRASES = [
    "you have won", "congratulations you", "claim your prize", "lucky winner",
    "lottery winner", "selected to receive", "free gift", "cash prize",
]

DELIVERY_PHRASES = [
    "package could not be delivered", "delivery failed", "shipment on hold",
    "reschedule your delivery", "customs fee", "parcel is waiting", "tracking number",
]

TECH_SUPPORT_PHRASES = [
    "microsoft support", "your computer has a virus", "call this number immediately",
    "windows defender alert", "your device is infected", "technical support team",
    "remote access", "your license has expired",
]

BEC_PHRASES = [
    "wire the funds", "keep this confidential", "are you at your desk",
    "change of bank account", "new payment instructions", "urgent request from the ceo",
    "i need you to process", "can you handle this discreetly",
]
