export interface OwaspCheck {
  id: string;
  name: string;
  nameHe: string;
  detectability: "full" | "partial" | "none";
  sastDetectability: "full" | "partial" | "none";
  reasonHe: string;
  sastReasonHe: string;
}

export const OWASP_CHECKS: Record<string, OwaspCheck> = {
  "A01:2025": {
    id: "A01",
    name: "Broken Access Control",
    nameHe: "בקרת גישה לקויה",
    detectability: "full",
    sastDetectability: "none",
    reasonHe: "סריקת ZAP לגישה לא מורשית + תבניות nuclei לחשיפת מידע",
    sastReasonHe: "לא ניתן לזהות באמצעות SAST — נדרש DAST",
  },
  "A02:2025": {
    id: "A02",
    name: "Security Misconfiguration",
    nameHe: "תצורת אבטחה שגויה",
    detectability: "full",
    sastDetectability: "none",
    reasonHe: "ניתוח כותרות HTTP, nikto, חוקי תצורה של ZAP, ו-testssl.sh",
    sastReasonHe: "לא ניתן לזהות באמצעות SAST — נדרש DAST",
  },
  "A03:2025": {
    id: "A03",
    name: "Software Supply Chain Failures",
    nameHe: "כשלי שרשרת אספקת תוכנה",
    detectability: "none",
    sastDetectability: "full",
    reasonHe: "לא ניתן לזהות באמצעות DAST — נדרש SAST/SCA על קוד המקור",
    sastReasonHe: "osv-scanner + trivy בודקים קבצי נעילה ותלויות מול מסדי נתוני פגיעויות לזיהוי CVE ידועים.",
  },
  "A04:2025": {
    id: "A04",
    name: "Cryptographic Failures",
    nameHe: "כשלים קריפטוגרפיים",
    detectability: "partial",
    sastDetectability: "none",
    reasonHe: "testssl.sh בודק TLS; ZAP מוצא עוגיות לא מאובטחות. לא בודק קריפטוגרפיה פנימית.",
    sastReasonHe: "לא ניתן לזהות באמצעות SAST — נדרש DAST",
  },
  "A05:2025": {
    id: "A05",
    name: "Injection",
    nameHe: "הזרקה",
    detectability: "full",
    sastDetectability: "none",
    reasonHe: "חוקי הזרקה פעילים של ZAP (SQLi, XSS, הזרקת פקודות) + תבניות nuclei",
    sastReasonHe: "לא ניתן לזהות באמצעות SAST — נדרש DAST",
  },
  "A06:2025": {
    id: "A06",
    name: "Insecure Design",
    nameHe: "עיצוב לא מאובטח",
    detectability: "none",
    sastDetectability: "none",
    reasonHe: "פגמי עיצוב ארכיטקטוניים — לא ניתנים לזיהוי בסריקה אוטומטית",
    sastReasonHe: "פגמי עיצוב ארכיטקטוניים — לא ניתנים לזיהוי בסריקה אוטומטית",
  },
  "A07:2025": {
    id: "A07",
    name: "Authentication Failures",
    nameHe: "כשלי אימות",
    detectability: "partial",
    sastDetectability: "none",
    reasonHe: "בדיקות אימות ZAP, תבניות nuclei לסיסמאות ברירת מחדל. לא בודק כל לוגיקת אימות.",
    sastReasonHe: "לא ניתן לזהות באמצעות SAST — נדרש DAST",
  },
  "A08:2025": {
    id: "A08",
    name: "Software and Data Integrity Failures",
    nameHe: "כשלי שלמות תוכנה ונתונים",
    detectability: "none",
    sastDetectability: "partial",
    reasonHe: "בעיקר נוגע ל-CI/CD ותהליך הבנייה. לא ניתן לבדיקה מספקת באמצעות DAST.",
    sastReasonHe: "trivy מכסה שלמות תלויות ותצורת IaC/CI שגויה. זיוף מערכת הבנייה/צינור CI ו-SRI דורשים סקירה ידנית.",
  },
  "A09:2025": {
    id: "A09",
    name: "Security Logging & Alerting Failures",
    nameHe: "כשלי רישום והתראות אבטחה",
    detectability: "none",
    sastDetectability: "none",
    reasonHe: "לא ניתן לבדוק רישום מבחוץ — נדרשת גישה ללוגים ותצורת SIEM.",
    sastReasonHe: "לא ניתן לבדוק רישום מבחוץ — נדרשת גישה ללוגים ותצורת SIEM.",
  },
  "A10:2025": {
    id: "A10",
    name: "Mishandling of Exceptional Conditions",
    nameHe: "טיפול שגוי בחריגים",
    detectability: "partial",
    sastDetectability: "none",
    reasonHe: "חוקי ZAP לחשיפת שגיאות + stack traces. לא מזהה כל פער בטיפול בחריגים.",
    sastReasonHe: "לא ניתן לזהות באמצעות SAST — נדרש DAST",
  },
};

export const OWASP_2025: Record<string, string> = Object.fromEntries(
  Object.entries(OWASP_CHECKS).map(([k, v]) => [k, v.name]),
);

export const OWASP_KEYS = Object.keys(OWASP_CHECKS);

export const ALL_CHECK_IDS = OWASP_KEYS.map((k) => k.split(":")[0]);
export const QUICK_CHECK_IDS = ["A01", "A02", "A05"];
