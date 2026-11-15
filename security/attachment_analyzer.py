"""
Static attachment inspection. Attachments are NEVER opened, executed, or
scanned with an antivirus engine — this module only looks at filename,
extension, declared MIME type, and size.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from security.security_rules import (
    DANGEROUS_ATTACHMENT_EXTENSIONS, MACRO_OFFICE_EXTENSIONS, ARCHIVE_EXTENSIONS,
)


@dataclass
class AttachmentFinding:
    filename: str
    content_type: str
    size_bytes: int
    extension: str = ""
    is_dangerous_extension: bool = False
    is_macro_enabled: bool = False
    is_archive: bool = False
    double_extension: bool = False
    reasons: list = field(default_factory=list)
    risk_points: int = 0


def _extensions(filename: str) -> list:
    name = filename.lower()
    parts = name.split(".")
    return ["." + p for p in parts[1:]] if len(parts) > 1 else []


def analyze_attachment(att) -> AttachmentFinding:
    filename = att.filename or "unnamed_attachment"
    finding = AttachmentFinding(filename=filename, content_type=att.content_type, size_bytes=att.size_bytes)
    exts = _extensions(filename)
    finding.extension = exts[-1] if exts else ""
    reasons = []
    points = 0

    if finding.extension in DANGEROUS_ATTACHMENT_EXTENSIONS:
        finding.is_dangerous_extension = True
        points += 45
        reasons.append(f"Attachment has a potentially executable extension ({finding.extension}).")

    if finding.extension in MACRO_OFFICE_EXTENSIONS:
        finding.is_macro_enabled = True
        points += 30
        reasons.append(f"Attachment is a macro-enabled Office file ({finding.extension}), a common malware vector.")

    if finding.extension in ARCHIVE_EXTENSIONS:
        finding.is_archive = True
        points += 12
        reasons.append(f"Attachment is an archive ({finding.extension}); its real contents cannot be verified without extraction.")

    if len(exts) >= 2:
        finding.double_extension = True
        points += 25
        reasons.append(
            f"Attachment name has multiple extensions ('{filename}'), a technique used to "
            "disguise executable files as documents."
        )

    if finding.size_bytes == 0:
        reasons.append("Attachment content could not be read/decoded for size verification.")

    if not reasons:
        reasons.append("No static red flags found in filename/extension/type; this is not a malware scan.")

    finding.risk_points = min(100, points)
    finding.reasons = reasons
    return finding


def analyze_attachments(attachments: list) -> dict:
    findings = [analyze_attachment(a) for a in attachments]
    if not findings:
        return {
            "count": 0, "findings": [], "max_risk": 0,
            "note": "No attachments were found in this email.",
        }
    return {
        "count": len(findings),
        "findings": findings,
        "max_risk": max(f.risk_points for f in findings),
        "note": "Static filename/extension/MIME analysis only — attachments were not opened, "
                "executed, or scanned by an antivirus engine.",
    }
