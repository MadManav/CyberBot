"""
Incident Response Helper
Detects cybersecurity incidents and provides immediate action steps
"""

import re

# Incident patterns and keywords
INCIDENT_PATTERNS = {
    "clicked_link": {
        "keywords": ["clicked", "click", "opened", "link", "url", "website"],
        "severity": "high",
        "description": "User clicked a suspicious link"
    },
    "gave_otp": {
        "keywords": ["otp", "one time password", "verification code", "gave", "shared", "told"],
        "severity": "critical",
        "description": "User shared OTP/verification code"
    },
    "shared_card": {
        "keywords": ["card", "cvv", "credit card", "debit card", "card number", "entered", "filled"],
        "severity": "critical",
        "description": "User shared card/banking details"
    },
    "downloaded_file": {
        "keywords": ["downloaded", "download", "apk", "file", "attachment", "installed"],
        "severity": "high",
        "description": "User downloaded suspicious file"
    },
    "account_hacked": {
        "keywords": ["hacked", "hack", "compromised", "accessed", "someone logged in", "unauthorized"],
        "severity": "critical",
        "description": "Account potentially compromised"
    },
    "gave_password": {
        "keywords": ["password", "gave password", "shared password", "told password"],
        "severity": "critical",
        "description": "User shared password"
    },
    "upi_fraud": {
        "keywords": ["upi", "paid", "payment", "gpay", "phonepe", "paytm", "wrong person"],
        "severity": "high",
        "description": "UPI payment fraud"
    },
    "fake_job": {
        "keywords": ["job", "work from home", "registration fee", "advance payment"],
        "severity": "medium",
        "description": "Fake job offer scam"
    }
}

def detect_incident(message):
    """
    Detect what type of cybersecurity incident occurred
    
    Args:
        message (str): User's message describing the incident
        
    Returns:
        dict: Incident details with type, severity, and confidence
    """
    if not message or not isinstance(message, str):
        return None
    
    message_lower = message.lower()
    
    # Check for incident indicators
    detected_incidents = []
    
    for incident_type, config in INCIDENT_PATTERNS.items():
        # Count how many keywords match
        matches = sum(1 for keyword in config["keywords"] if keyword in message_lower)
        
        if matches >= 2:  # Need at least 2 keywords to confirm
            confidence = min(matches / len(config["keywords"]), 1.0)
            detected_incidents.append({
                "type": incident_type,
                "severity": config["severity"],
                "description": config["description"],
                "confidence": confidence
            })
    
    # Return the highest confidence incident
    if detected_incidents:
        detected_incidents.sort(key=lambda x: x["confidence"], reverse=True)
        return detected_incidents[0]
    
    return None


def get_incident_response(incident_type):
    """
    Get immediate action steps for the incident
    
    Args:
        incident_type (str): Type of incident detected
        
    Returns:
        dict: Response with immediate actions, prevention tips, and resources
    """
    
    responses = {
        "clicked_link": {
            "immediate_actions": [
                "🚨 **Disconnect from internet immediately** (WiFi/Mobile Data)",
                "🔒 **Do NOT enter any passwords or OTPs** if any page asks",
                "📱 **Clear browser cache and history**",
                "🔐 **Change passwords** for important accounts (from another device)",
                "💳 **Check bank statements** for unauthorized transactions",
                "📞 **Enable 2-factor authentication** on all accounts"
            ],
            "prevention": [
                "✅ Always verify sender before clicking links",
                "✅ Hover over links to see actual URL",
                "✅ Look for HTTPS and legitimate domain names",
                "✅ Use antivirus software with real-time protection"
            ],
            "urgency": "high"
        },
        
        "gave_otp": {
            "immediate_actions": [
                "🚨 **CRITICAL: Contact your bank immediately** (Call official number from back of card)",
                "🔒 **Block your card/UPI** through banking app",
                "📱 **Change bank account password** and UPI PIN",
                "💳 **Check transaction history** for unauthorized activity",
                "📞 **File complaint** at cybercrime.gov.in within 24 hours",
                "⚠️ **Don't share OTP with anyone again** - Banks NEVER ask for OTP"
            ],
            "prevention": [
                "🚫 NEVER share OTP with anyone (not even bank officials)",
                "🚫 Banks/Government never ask for OTP on call",
                "✅ OTP is only for YOUR transactions",
                "✅ Always verify caller identity independently"
            ],
            "urgency": "critical"
        },
        
        "shared_card": {
            "immediate_actions": [
                "🚨 **Call bank immediately** and block your card",
                "💳 **Report as stolen/compromised** to freeze transactions",
                "📱 **Check last 5 transactions** for fraud",
                "🔐 **Change online banking password** immediately",
                "📞 **File FIR and cybercrime complaint** (important for insurance)",
                "⚠️ **Request new card** with different number"
            ],
            "prevention": [
                "🚫 Never share CVV, PIN, or card details on call/SMS",
                "✅ Only use secure websites (check for HTTPS)",
                "✅ Enable transaction alerts via SMS",
                "✅ Use virtual cards for online shopping"
            ],
            "urgency": "critical"
        },
        
        "downloaded_file": {
            "immediate_actions": [
                "🚨 **Turn off internet** immediately",
                "🗑️ **Delete the downloaded file** (don't open it)",
                "🛡️ **Run full antivirus scan** on your device",
                "📱 **Uninstall recently installed apps**",
                "🔐 **Change passwords** (from another safe device)",
                "💾 **Backup important data** to external drive",
                "⚠️ **Factory reset** if device behaving strangely"
            ],
            "prevention": [
                "🚫 Don't download APKs from unknown sources",
                "✅ Only use Google Play Store/App Store",
                "✅ Check app permissions before installing",
                "✅ Keep antivirus software updated"
            ],
            "urgency": "high"
        },
        
        "account_hacked": {
            "immediate_actions": [
                "🚨 **Change password immediately** (from trusted device)",
                "📧 **Check email for password reset attempts**",
                "🔐 **Enable 2-factor authentication** (2FA)",
                "📱 **Review connected devices** and remove unknown ones",
                "⚠️ **Check account activity log** for suspicious logins",
                "📞 **Notify contacts** if hacker is sending messages",
                "🔒 **Update security questions** and recovery email"
            ],
            "prevention": [
                "✅ Use strong, unique passwords for each account",
                "✅ Enable 2FA on all important accounts",
                "✅ Never use public WiFi for banking/sensitive logins",
                "✅ Regularly check connected devices and active sessions"
            ],
            "urgency": "critical"
        },
        
        "gave_password": {
            "immediate_actions": [
                "🚨 **Change password NOW** on all accounts using that password",
                "📧 **Check email account** first (hackers change recovery email)",
                "🔐 **Enable 2-factor authentication** everywhere",
                "📱 **Review recent account activity** for unauthorized access",
                "⚠️ **Update security questions**",
                "💳 **Monitor bank accounts** closely for next 30 days"
            ],
            "prevention": [
                "🚫 NEVER share passwords with anyone",
                "✅ Use unique passwords for each account",
                "✅ Use password manager (Google Password Manager, Bitwarden)",
                "✅ Enable biometric login when available"
            ],
            "urgency": "critical"
        },
        
        "upi_fraud": {
            "immediate_actions": [
                "📞 **Call your bank immediately** (use number from app/card)",
                "💳 **Report transaction** in UPI app (tap on transaction → Report)",
                "🚨 **File complaint at cybercrime.gov.in** within 24 hours",
                "📱 **Call 1930** (National Cyber Crime Helpline)",
                "📄 **Screenshot transaction details** for evidence",
                "⚠️ **Don't accept calls** from scammer claiming refund"
            ],
            "prevention": [
                "✅ Always verify UPI ID before sending money",
                "✅ Never accept 'collect money' requests from strangers",
                "✅ Don't click UPI links in SMS/WhatsApp",
                "✅ Use UPI PIN instead of QR for unknown merchants"
            ],
            "urgency": "high"
        },
        
        "fake_job": {
            "immediate_actions": [
                "🚨 **Stop communication** with the scammer",
                "💰 **Don't send any more money** (registration/equipment fees)",
                "📞 **Report to cybercrime.gov.in** if you paid money",
                "📱 **Block sender** on all platforms",
                "⚠️ **Warn others** who might be targeted",
                "📄 **Screenshot all conversations** as evidence"
            ],
            "prevention": [
                "🚫 Legitimate companies never ask for upfront payment",
                "✅ Verify company on official website",
                "✅ Check reviews on Glassdoor/AmbitionBox",
                "✅ Be suspicious of 'work from home' with high pay"
            ],
            "urgency": "medium"
        }
    }
    
    return responses.get(incident_type, {
        "immediate_actions": [
            "🚨 Contact your service provider immediately",
            "📞 File complaint at cybercrime.gov.in",
            "💳 Monitor your accounts closely"
        ],
        "prevention": [
            "✅ Always verify before sharing information",
            "✅ Use strong passwords and 2FA"
        ],
        "urgency": "medium"
    })


def get_reporting_resources():
    """
    Get official reporting resources
    
    Returns:
        dict: Contact information for cybercrime reporting
    """
    return {
        "national_helpline": {
            "number": "1930",
            "description": "National Cyber Crime Helpline (24x7)",
            "languages": "English, Hindi, Regional"
        },
        "online_portal": {
            "url": "https://cybercrime.gov.in",
            "description": "Report cybercrime online",
            "note": "File complaint within 24-48 hours for best results"
        },
        "women_helpline": {
            "number": "7997799777",
            "description": "Cyber Crime Helpline for Women"
        },
        "child_helpline": {
            "number": "1098",
            "description": "CHILDLINE India (for minors)"
        },
        "bank_fraud": {
            "action": "Call bank customer care immediately",
            "note": "Use number on back of card, not from SMS/email"
        }
    }