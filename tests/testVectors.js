/**
 * Comprehensive Curated Test Vectors for Heuristic & Threat Engine Verification
 * Contains balanced benign, suspicious, and malicious vectors to evaluate false positives and false negatives.
 */

export const TEST_VECTORS = {
    urls: [
        // Malicious / Suspicious Vectors (Adversarial)
        {
            input: 'http://paypa1-security-login.ru/verify?token=98234',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS', 'SUSPICIOUS'],
            shouldTrigger: ['BRAND_TYPOSQUATTING_DETECTED', 'ELEVATED_RISK_TLD', 'SUSPICIOUS_LURE_KEYWORDS']
        },
        {
            input: 'https://xn--pple-43d.com/login',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS', 'SUSPICIOUS'],
            shouldTrigger: ['HOMOGLYPH_IDN_SPOOFING']
        },
        {
            input: 'http://192.168.1.100:8080/admin/auth',
            expectedVerdict: ['SUSPICIOUS', 'HIGH_RISK'],
            shouldTrigger: ['HOST_IP_ADDRESS', 'NON_STANDARD_PORT']
        },
        {
            input: 'https://paypal.com.account-verification.ru/signin',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS', 'SUSPICIOUS'],
            shouldTrigger: ['BRAND_TYPOSQUATTING_DETECTED']
        },
        {
            input: 'https://legit-portal.com@evil-phish-domain.top/auth',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS', 'SUSPICIOUS'],
            shouldTrigger: ['AUTH_CREDENTIAL_INJECTION', 'ELEVATED_RISK_TLD']
        },
        {
            input: 'https://a.b.c.d.e.f.bank-portal.xyz/login',
            expectedVerdict: ['SUSPICIOUS', 'HIGH_RISK'],
            shouldTrigger: ['DEEP_SUBDOMAIN_NESTING', 'ELEVATED_RISK_TLD']
        },
        {
            input: 'http://bit.ly/3xWin-claim-reward-now',
            expectedVerdict: ['SUSPICIOUS', 'HIGH_RISK'],
            shouldTrigger: ['URL_SHORTENER_DETECTED']
        },
        {
            input: 'https://auth-portal.com/redirect?url=http://malicious-target.xyz/login',
            expectedVerdict: ['SUSPICIOUS', 'HIGH_RISK'],
            shouldTrigger: ['POTENTIAL_OPEN_REDIRECT']
        },
        {
            input: 'http://update-service.com/payload/patch.exe',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS', 'SUSPICIOUS'],
            shouldTrigger: ['DANGEROUS_DOWNLOAD_EXTENSION']
        },

        // Benign / Legitimate Real-World URLs (False Positive Prevention)
        {
            input: 'https://google.com/search?q=cybersecurity+threat+intelligence',
            expectedVerdict: ['SAFE'],
            shouldNotTrigger: ['BRAND_TYPOSQUATTING_DETECTED', 'HOMOGLYPH_IDN_SPOOFING', 'HOST_IP_ADDRESS']
        },
        {
            input: 'https://github.com/fastapi/full-stack-fastapi-template',
            expectedVerdict: ['SAFE'],
            shouldNotTrigger: ['ELEVATED_RISK_TLD', 'BRAND_TYPOSQUATTING_DETECTED']
        },
        {
            input: 'https://aws.amazon.com/console/home?region=us-east-1#services',
            expectedVerdict: ['SAFE'],
            shouldNotTrigger: ['BRAND_TYPOSQUATTING_DETECTED', 'AUTH_CREDENTIAL_INJECTION']
        },
        {
            input: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy',
            expectedVerdict: ['SAFE'],
            shouldNotTrigger: ['SUSPICIOUS_LURE_KEYWORDS', 'DEEP_SUBDOMAIN_NESTING']
        },
        {
            input: 'https://www.irs.gov/individuals/get-transcript',
            expectedVerdict: ['SAFE'],
            shouldTrigger: ['HIGH_TRUST_TLD'],
            shouldNotTrigger: ['ELEVATED_RISK_TLD']
        },
        {
            input: 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
            expectedVerdict: ['SAFE'],
            shouldNotTrigger: ['DANGEROUS_DOWNLOAD_EXTENSION']
        }
    ],

    messages: [
        // Malicious / Scam SMS
        {
            input: 'URGENT: Your SBI account has been locked due to missing KYC. Update immediately at http://sbi-secure.ru/verify within 24 hours to avoid suspension.',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS'],
            shouldTrigger: ['PSYCHOLOGICAL_URGENCY_TRIGGER', 'BANK_ACCOUNT_KYC_ACTION', 'EMBEDDED_SUSPICIOUS_LINK']
        },
        {
            input: 'Congratulations! You have won a cash reward of $5,000. Send your OTP to claim now.',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS'],
            shouldTrigger: ['PRIZE_LOTTERY_SCAM', 'CREDENTIAL_OTP_HARVESTING']
        },
        {
            input: 'USPS Notice: Your package delivery failed due to unpaid customs fee of $2.40. Reschedule delivery at http://usps-parcel-held.xyz immediately.',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS'],
            shouldTrigger: ['PACKAGE_DELIVERY_SCAM', 'EMBEDDED_SUSPICIOUS_LINK']
        },
        {
            input: 'Final Warning: Legal action initiated against your account. Pay $450 in fines today to avoid arrest summons.',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS'],
            shouldTrigger: ['PSYCHOLOGICAL_URGENCY_TRIGGER']
        },

        // Benign Communications & Security Advisories
        {
            input: 'Hi Anand, the team sync is scheduled for 3 PM today in Conference Room B.',
            expectedVerdict: ['SAFE'],
            shouldNotTrigger: ['PSYCHOLOGICAL_URGENCY_TRIGGER', 'CREDENTIAL_OTP_HARVESTING']
        },
        {
            input: 'HDFC Bank Alert: Never share your OTP or netbanking password with anyone. Our representatives will never ask for your confidential codes.',
            expectedVerdict: ['SAFE', 'SUSPICIOUS'],
            shouldTrigger: ['SECURITY_ADVISORY_NOTICE'],
            shouldNotTrigger: ['CREDENTIAL_OTP_HARVESTING']
        },
        {
            input: 'Your Amazon package #112-4982391 has been delivered to your front porch. Thank you for shopping with us.',
            expectedVerdict: ['SAFE'],
            shouldNotTrigger: ['PSYCHOLOGICAL_URGENCY_TRIGGER']
        }
    ],

    emails: [
        // Malicious Phishing Emails
        {
            input: 'From: "PayPal Security" <billing-alert98@gmail.com>\nSubject: Action Required: Your account is suspended\n\nPlease verify your credentials at http://paypal-reauth.xyz',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS'],
            shouldTrigger: ['EMAIL_DISPLAY_NAME_SPOOFING', 'PSYCHOLOGICAL_URGENCY_TRIGGER']
        },
        {
            input: 'From: "CEO Office" <urgent-wire@temporary-mail.top>\nSubject: URGENT: Wire Transfer Authorization Required\n\nInitiate $45,000 wire to vendor immediately to avoid contract default.',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS'],
            shouldTrigger: ['PSYCHOLOGICAL_URGENCY_TRIGGER', 'FINANCIAL_TRANSACTION_FRAUD']
        },

        // Benign Legitimate Emails
        {
            input: 'From: support@github.com\nSubject: [GitHub] A personal access token has expired\n\nYour token "dev-token-1" expired today. If no longer needed, no action is required.',
            expectedVerdict: ['SAFE', 'SUSPICIOUS'],
            shouldNotTrigger: ['EMAIL_DISPLAY_NAME_SPOOFING']
        },
        {
            input: 'From: notifications@zoom.us\nSubject: Meeting Invitation: Architecture Review\n\nJoin the Zoom meeting at 10:00 AM PST.',
            expectedVerdict: ['SAFE'],
            shouldNotTrigger: ['EMAIL_DISPLAY_NAME_SPOOFING']
        }
    ],

    apks: [
        // Suspicious / Shadowed APK Package Names
        {
            input: 'com.whatsapp.update.pro.free.unlimited',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS'],
            shouldTrigger: ['OFFICIAL_APP_SHADOWING', 'MOD_HACK_FRAUD_KEYWORDS']
        },
        {
            input: 'com.android.system.security.patch.installer',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS'],
            shouldTrigger: ['FAKE_SYSTEM_PACKAGE_MIMICRY']
        },
        {
            input: 'com.free.gems.generator.clash.royale',
            expectedVerdict: ['HIGH_RISK', 'MALICIOUS'],
            shouldTrigger: ['MOD_HACK_FRAUD_KEYWORDS']
        },

        // Benign Standard Android Package Names
        {
            input: 'com.google.android.youtube',
            expectedVerdict: ['SAFE'],
            shouldNotTrigger: ['OFFICIAL_APP_SHADOWING', 'FAKE_SYSTEM_PACKAGE_MIMICRY']
        },
        {
            input: 'org.mozilla.firefox',
            expectedVerdict: ['SAFE'],
            shouldNotTrigger: ['OFFICIAL_APP_SHADOWING', 'FAKE_SYSTEM_PACKAGE_MIMICRY']
        },
        {
            input: 'com.spotify.music',
            expectedVerdict: ['SAFE'],
            shouldNotTrigger: ['OFFICIAL_APP_SHADOWING']
        }
    ]
};

