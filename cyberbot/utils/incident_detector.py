"""
Incident Response Helper (CyberGuard AI)
Detects cybersecurity incidents and provides immediate action steps.
"""

import re

# ================= INCIDENT PATTERNS ===================
INCIDENT_PATTERNS = {
    "clicked_link": {
        "keywords": [
            "clicked", "click", "opened", "tapped", "visited", "pressed link",
            "followed link", "link from message", "link from whatsapp",
            "opened url", "opened website", "clicked suspicious link",
            "visited site", "opened that page", "went to website", "opened mail link"
        ],
        "severity": "high",
        "description": "User clicked a suspicious link"
    },

    "gave_otp": {
        "keywords": [
            "otp", "o t p", "verification code", "one time password", "security code",
            "6 digit", "shared otp", "gave otp", "told otp", "read the code",
            "shared code", "entered otp", "entered verification code", "forwarded otp",
            "they asked for otp", "entered sms code", "told them my otp"
        ],
        "severity": "critical",
        "description": "User shared OTP or verification code"
    },

    "shared_card": {
        "keywords": [
            "card", "cvv", "atm pin", "pin", "card number", "credit card", "debit card",
            "bank details", "account number", "ifsc", "shared card", "entered cvv",
            "gave card details", "filled bank form", "shared banking info"
        ],
        "severity": "critical",
        "description": "User shared card or banking details"
    },

    "downloaded_file": {
        "keywords": [
            "downloaded", "download", "apk", "installed", "file", "attachment",
            "document", "pdf", "exe", "zip", "opened file", "clicked download",
            "got attachment", "installed app", "downloaded app from whatsapp"
        ],
        "severity": "high",
        "description": "User downloaded suspicious file or app"
    },

    "account_hacked": {
        "keywords": [
            "hacked", "compromised", "unauthorized", "account stolen", "lost access",
            "account taken over", "someone changed password", "logged in without me",
            "account accessed", "password reset by someone"
        ],
        "severity": "critical",
        "description": "Account potentially compromised"
    },

    "gave_password": {
        "keywords": [
            "password", "shared password", "told password", "entered password",
            "sent password", "typed password", "shared login info", "gave credentials"
        ],
        "severity": "critical",
        "description": "User shared password or login credentials"
    },

    "upi_fraud": {
        "keywords": [
            "upi", "gpay", "google pay", "phonepe", "paytm", "bhim", "sent money",
            "scanned qr", "qr code", "requested money", "wrong person", "refund link",
            "upi id", "they told me to scan", "money request", "payment done"
        ],
        "severity": "high",
        "description": "UPI payment fraud or scam"
    },

    "fake_job": {
        "keywords": [
            "job", "work from home", "registration fee", "joining fee",
            "application fee", "telegram job", "paid to join", "job offer",
            "task based job", "part time job", "asked money for job"
        ],
        "severity": "medium",
        "description": "Fake job or work-from-home scam"
    },

    "kyc_fraud": {
        "keywords": [
            "kyc", "update kyc", "account blocked", "account frozen", "verify account",
            "reactivate account", "verify details", "bank message", "rbi", "bank link",
            "your account will be blocked", "update kyc immediately", "bank sms"
        ],
        "severity": "high",
        "description": "Fake KYC or bank account scam"
    },

    "impersonation": {
        "keywords": [
            "someone pretending", "impersonating", "posing as", "fake account",
            "duplicate profile", "used my photo", "same name", "fake id", "pretending to be"
        ],
        "severity": "high",
        "description": "Fake or impersonation attempt"
    },

    "electricity_scam": {
        "keywords": [
            "electricity bill", "power cut", "bijli bill", "payment pending",
            "disconnection", "electric board", "bill payment link", "service cut off"
        ],
        "severity": "medium",
        "description": "Fake electricity bill or disconnection scam"
    },

    "investment_scam": {
        "keywords": [
            "investment", "crypto", "bitcoin", "stock", "profit", "returns",
            "earn daily", "trading app", "double money", "forex", "trading group"
        ],
        "severity": "medium",
        "description": "Fake investment or crypto scam"
    },

    "refund_scam": {
        "keywords": [
            "refund", "return money", "cashback", "call from amazon", "parcel", "courier",
            "fedex", "delivery issue", "import tax", "payment refund", "refund form"
        ],
        "severity": "medium",
        "description": "Fake refund or delivery-related scam"
    },

    "loan_scam": {
        "keywords": [
            "loan", "instant loan", "personal loan", "approval fee", "loan app",
            "low interest", "registration fee for loan", "easy loan", "fake loan"
        ],
        "severity": "medium",
        "description": "Fake loan or finance app scam"
    },

    "tech_support_scam": {
        "keywords": [
            "technical support", "microsoft support", "computer problem", "virus alert",
            "call microsoft", "remote access", "install software", "told me to download anydesk",
            "remote control", "helpdesk call"
        ],
        "severity": "high",
        "description": "Fake tech support or remote access scam"
    },

    "romance_scam": {
        "keywords": [
            "boyfriend", "girlfriend", "online friend", "asked money", "love scam",
            "romance", "met online", "dating app", "foreign partner", "gift parcel scam"
        ],
        "severity": "medium",
        "description": "Online romance or relationship-based scam"
    },

    "government_scam": {
        "keywords": [
            "income tax", "pan", "aadhar", "government call", "cbic", "customs", "rbi",
            "income tax refund", "govt officer", "official notice", "legal action"
        ],
        "severity": "medium",
        "description": "Fake government or tax-related scam"
    }
}


# =============== INCIDENT DETECTION =====================
def detect_incident(message):
    """
    Detect type of cybersecurity incident from user message.
    """
    if not message or not isinstance(message, str):
        return None

    message_lower = message.lower()
    detected_incidents = []

    for incident_type, config in INCIDENT_PATTERNS.items():
        matches = sum(1 for keyword in config["keywords"] if keyword in message_lower)
        if matches >= 2:
            confidence = min(matches / len(config["keywords"]), 1.0)
            detected_incidents.append({
                "type": incident_type,
                "severity": config["severity"],
                "description": config["description"],
                "confidence": confidence
            })

    if detected_incidents:
        detected_incidents.sort(key=lambda x: x["confidence"], reverse=True)
        return detected_incidents[0]

    return None


# =============== INCIDENT RESPONSE RECOMMENDATIONS =====================
def get_incident_response(incident_type):
    RESPONSES = {
        "clicked_link": {
            "immediate_actions": [
                "🚨 Disconnect from the internet immediately.",
                "🧹 Clear browser cache and history.",
                "🔐 Change your important passwords."
            ],
            "prevention": [
                "✅ Verify links before clicking.",
                "✅ Avoid opening unknown URLs."
            ]
        },
        "gave_otp": {
            "immediate_actions": [
                "🚨 Call your bank and block your account immediately.",
                "📞 Report to the cybercrime helpline at 1930."
            ],
            "prevention": [
                "🚫 Never share OTP or verification codes.",
                "✅ Banks never ask for OTPs."
            ]
        },
        "shared_card": {
            "immediate_actions": [
                "💳 Block your card immediately via mobile banking.",
                "📞 Inform your bank’s customer care."
            ],
            "prevention": [
                "🚫 Don’t share card or CVV details.",
                "✅ Use trusted payment apps only."
            ]
        }
    }

    return RESPONSES.get(incident_type, {
        "immediate_actions": ["⚠️ Stay alert and report suspicious activities."],
        "prevention": ["✅ Verify sources before acting."]
    })


# =============== REPORTING RESOURCES =====================
def get_reporting_resources():
    return {
        "national_helpline": {
            "number": "1930",
            "description": "National Cyber Crime Helpline (24x7)"
        },
        "online_portal": {
            "url": "https://cybercrime.gov.in",
            "description": "Report cybercrime online (official govt site)"
        },
        "bank_fraud": {
            "action": "Call your bank’s customer care immediately using the number printed on your card."
        },
        "women_helpline": {
            "number": "7997799777",
            "description": "Cyber Crime Helpline for Women"
        },
        "child_helpline": {
            "number": "1098",
            "description": "CHILDLINE India (for minors)"
        }
    }
