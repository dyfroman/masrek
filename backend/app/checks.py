"""Check registry — one check per OWASP Top 10:2025 category.

Each check declares which scanner tools it needs, its DAST detectability level,
and a human-readable explanation of what is and isn't testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Check:
    id: str
    name: str
    name_he: str
    tools: list[str] = field(default_factory=list)
    active_tools: list[str] = field(default_factory=list)
    sast_tools: list[str] = field(default_factory=list)
    detectability: str = "none"
    sast_detectability: str = "none"
    combined_detectability: str = "none"
    reason: str = ""
    reason_he: str = ""
    sast_reason: str = ""
    sast_reason_he: str = ""


CHECKS: dict[str, Check] = {
    "A01": Check(
        id="A01",
        name="Broken Access Control",
        name_he="בקרת גישה לקויה",
        tools=["zap", "nuclei"],
        active_tools=["zap", "nuclei"],
        detectability="full",
        reason="ZAP forced-browse + access-control rules, nuclei exposure/IDOR templates",
        reason_he="סריקת ZAP לגישה לא מורשית + תבניות nuclei לחשיפת מידע",
    ),
    "A02": Check(
        id="A02",
        name="Security Misconfiguration",
        name_he="תצורת אבטחה שגויה",
        tools=["passive-headers", "nikto", "zap", "testssl"],
        active_tools=["nikto", "zap"],
        detectability="full",
        reason="Passive headers analysis, nikto, ZAP config/error rules, testssl.sh",
        reason_he="ניתוח כותרות HTTP, nikto, חוקי תצורה של ZAP, ו-testssl.sh",
    ),
    "A03": Check(
        id="A03",
        name="Software Supply Chain Failures",
        name_he="כשלי שרשרת אספקת תוכנה",
        tools=[],
        active_tools=[],
        sast_tools=["osv-scanner"],
        detectability="none",
        sast_detectability="full",
        combined_detectability="full",
        reason="DAST cannot inspect dependencies — requires SAST/SCA (e.g. osv-scanner, trivy) on source code",
        reason_he="לא ניתן לזהות באמצעות DAST — נדרש SAST/SCA על קוד המקור",
        sast_reason="osv-scanner checks lockfiles against the OSV vulnerability database for known CVEs in dependencies.",
        sast_reason_he="osv-scanner בודק קבצי נעילה מול מסד נתוני הפגיעויות OSV לזיהוי CVE ידועים בתלויות.",
    ),
    "A04": Check(
        id="A04",
        name="Cryptographic Failures",
        name_he="כשלים קריפטוגרפיים",
        tools=["testssl", "zap"],
        active_tools=["zap"],
        detectability="partial",
        reason="testssl.sh covers TLS config; ZAP finds insecure cookies/mixed-content. Cannot test internal crypto logic.",
        reason_he="testssl.sh בודק תצורת TLS; ZAP מוצא עוגיות לא מאובטחות. לא ניתן לבדוק לוגיקה קריפטוגרפית פנימית.",
    ),
    "A05": Check(
        id="A05",
        name="Injection",
        name_he="הזרקה",
        tools=["zap", "nuclei"],
        active_tools=["zap", "nuclei"],
        detectability="full",
        reason="ZAP active injection rules (SQLi, XSS, command injection) + nuclei injection templates",
        reason_he="חוקי הזרקה פעילים של ZAP (SQLi, XSS, הזרקת פקודות) + תבניות nuclei",
    ),
    "A06": Check(
        id="A06",
        name="Insecure Design",
        name_he="עיצוב לא מאובטח",
        tools=[],
        active_tools=[],
        detectability="none",
        reason="Design flaws are architectural — not detectable by automated scanning. Requires threat modeling and design review.",
        reason_he="פגמי עיצוב הם ארכיטקטוניים — לא ניתנים לזיהוי בסריקה אוטומטית. נדרש מודל איומים וסקירת עיצוב.",
    ),
    "A07": Check(
        id="A07",
        name="Authentication Failures",
        name_he="כשלי אימות",
        tools=["zap", "nuclei"],
        active_tools=["zap", "nuclei"],
        detectability="partial",
        reason="ZAP auth tests, nuclei default-login templates. Rate-limited, non-destructive. Cannot test all auth logic.",
        reason_he="בדיקות אימות ZAP, תבניות nuclei לסיסמאות ברירת מחדל. מוגבל קצב, לא הרסני. לא בודק את כל לוגיקת האימות.",
    ),
    "A08": Check(
        id="A08",
        name="Software and Data Integrity Failures",
        name_he="כשלי שלמות תוכנה ונתונים",
        tools=[],
        active_tools=[],
        detectability="none",
        reason="Mostly a CI/CD and build-pipeline concern (SRI, CSP). Not sufficiently testable via external DAST.",
        reason_he="בעיקר נוגע ל-CI/CD ותהליך הבנייה. לא ניתן לבדיקה מספקת באמצעות DAST חיצוני.",
    ),
    "A09": Check(
        id="A09",
        name="Security Logging & Alerting Failures",
        name_he="כשלי רישום והתראות אבטחה",
        tools=[],
        active_tools=[],
        detectability="none",
        reason="Logging adequacy cannot be observed externally — requires access to application logs and SIEM configuration.",
        reason_he="לא ניתן לבדוק רישום מבחוץ — נדרשת גישה ללוגים ותצורת SIEM.",
    ),
    "A10": Check(
        id="A10",
        name="Mishandling of Exceptional Conditions",
        name_he="טיפול שגוי בחריגים",
        tools=["zap", "nuclei"],
        active_tools=["zap", "nuclei"],
        detectability="partial",
        reason="ZAP error-disclosure/stack-trace rules + error probing. Cannot detect all internal exception handling gaps.",
        reason_he="חוקי ZAP לחשיפת שגיאות + stack traces. לא ניתן לזהות את כל הפערים בטיפול בחריגים.",
    ),
}

ALL_CHECK_IDS = sorted(CHECKS.keys())
QUICK_CHECK_IDS = ["A01", "A02", "A05"]


def checks_need_tool(selected: list[str], tool: str) -> bool:
    """Return True if any selected check needs the given active-stage tool."""
    for cid in selected:
        check = CHECKS.get(cid)
        if check and tool in check.active_tools:
            return True
    return False


def checks_need_sast_tool(selected: list[str], tool: str) -> bool:
    """Return True if any selected check needs the given SAST/SCA tool."""
    for cid in selected:
        check = CHECKS.get(cid)
        if check and tool in check.sast_tools:
            return True
    return False


def get_sast_not_testable_checks(selected: list[str]) -> list[Check]:
    """Return selected checks with sast_detectability=none (needs DAST instead)."""
    return [
        CHECKS[cid]
        for cid in selected
        if cid in CHECKS and CHECKS[cid].sast_detectability == "none"
    ]


def get_sast_partial_checks(selected: list[str]) -> list[Check]:
    """Return selected checks with sast_detectability=partial."""
    return [
        CHECKS[cid]
        for cid in selected
        if cid in CHECKS and CHECKS[cid].sast_detectability == "partial"
    ]


def get_not_testable_checks(selected: list[str]) -> list[Check]:
    """Return selected checks with detectability=none."""
    return [
        CHECKS[cid]
        for cid in selected
        if cid in CHECKS and CHECKS[cid].detectability == "none"
    ]


def get_partial_checks(selected: list[str]) -> list[Check]:
    """Return selected checks with detectability=partial."""
    return [
        CHECKS[cid]
        for cid in selected
        if cid in CHECKS and CHECKS[cid].detectability == "partial"
    ]
