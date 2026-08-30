/**
 * Social Engineering & Attack Vector Classifier for Text Payloads
 * Incorporates contextual negation checks to prevent false alarms on security notices.
 */

const VECTOR_PATTERNS = [
    {
        id: 'CREDENTIAL_OTP_HARVESTING',
        category: 'Credential Harvesting',
        severity: 'danger',
        regex: /\b(send (your )?otp|enter (your )?otp|share (your )?otp|verify (your )?password|confirm (your )?password|provide (your )?pin|provide (your )?cvv|submit (your )?credentials|2fa code is required to avoid)\b/i,
        weight: 35,
        title: 'Sensitive Credential / OTP Solicitation Lure',
        description: 'Directly requests one-time passcodes (OTP), login credentials, or security PINs. Legitimate institutions never ask users to submit passcodes via unverified chat/SMS channels.'
    },
    {
        id: 'FINANCIAL_TRANSACTION_FRAUD',
        category: 'Financial Fraud',
        severity: 'danger',
        regex: /\b(wire transfer|refund of (rs|\$|usd|inr|eur)|credited to your account|deducted from your card|direct deposit pending|tax refund notice|overdue payment of|unclaimed funds)\b/i,
        weight: 30,
        title: 'Financial Transaction / Refund Bait',
        description: 'References unsolicited monetary refunds, wire transfers, or unexpected bank deductions designed to trigger immediate engagement.'
    },
    {
        id: 'PRIZE_LOTTERY_SCAM',
        category: 'Reward & Advance-Fee Fraud',
        severity: 'danger',
        regex: /\b(congratulations|you('ve)? won|lottery winner|cash prize|free iphone|selected for (a )?\$|claim reward|exclusive gift)\b/i,
        weight: 30,
        title: 'Prize / Lottery Advance-Fee Lure',
        description: 'Promises unrealistic high-value rewards, lottery winnings, or promotional giveaways requiring link clicks.'
    },
    {
        id: 'PACKAGE_DELIVERY_SCAM',
        category: 'Impersonation',
        severity: 'warning',
        regex: /\b(delivery failed|package (pending|held|delayed)|customs fee required|reschedule delivery|usps parcel|fedex tracking update|dhl shipment held)\b/i,
        weight: 25,
        title: 'Fake Delivery Notification (Smishing/Phishing)',
        description: 'Claims an undelivered parcel or unpaid shipment fee requires urgent confirmation. One of the most prevalent smishing vectors.'
    },
    {
        id: 'BANK_ACCOUNT_KYC_ACTION',
        category: 'Financial Fraud',
        severity: 'danger',
        regex: /\b(pan card|aadhaar|kyc|sbi account|hdfc alert|icici update|update your bank details|account.*locked.*kyc|kyc.*missing)\b/i,
        weight: 35,
        title: 'Banking / Mandatory KYC Update Vector',
        description: 'Impersonates banking regulatory compliance or KYC re-verification to coerce users into submitting personal identity documents.'
    },
    {
        id: 'LEGAL_EXTORTION_THREAT',
        category: 'Social Engineering',
        severity: 'danger',
        regex: /\b(legal action initiated|arrest summons|court penalty|fines today|law enforcement warrant|police complaint filed)\b/i,
        weight: 35,
        title: 'Legal Coercion & Law Enforcement Extortion Lure',
        description: 'Threatens immediate criminal proceedings, warrants, or fines to induce panic and compliance.'
    }
];

// Legitimate security advisories often include defensive warnings that should negate false positive triggers
const DEFENSIVE_SECURITY_ADVISORIES = [
    /\b(never share|do not share|don't share|will never ask for|keep your otp secret|for your security|if you did not request this|no action is required)\b/i
];

export function analyzeSocialEngineering(text) {
    if (!text || typeof text !== 'string') return { indicators: [], score: 0, matchedVectors: [] };

    const indicators = [];
    const matchedVectors = [];
    let totalScore = 0;

    // Check for defensive advisory context
    const isDefensiveAdvisory = DEFENSIVE_SECURITY_ADVISORIES.some(reg => reg.test(text));

    for (const vector of VECTOR_PATTERNS) {
        if (vector.regex.test(text)) {
            // If it's a defensive security notice (e.g. "Never share your OTP with anyone"), attenuate severity
            if (vector.id === 'CREDENTIAL_OTP_HARVESTING' && isDefensiveAdvisory) {
                indicators.push({
                    id: 'SECURITY_ADVISORY_NOTICE',
                    category: 'Security Advisory',
                    severity: 'info',
                    title: 'Defensive Security Advisory Language Observed',
                    description: 'Message appears to be an official security notification warning against sharing credentials.'
                });
                continue;
            }

            matchedVectors.push(vector.category);
            totalScore += vector.weight;
            indicators.push({
                id: vector.id,
                category: vector.category,
                severity: vector.severity,
                title: vector.title,
                description: vector.description
            });
        }
    }

    return {
        indicators,
        score: Math.min(70, totalScore),
        matchedVectors
    };
}

