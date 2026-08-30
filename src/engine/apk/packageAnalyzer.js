/**
 * Android Package (APK) Namespace & Identifier Security Analyzer
 * Note: Analyzes reverse-domain naming conventions, brand shadowing, and malware naming patterns.
 */

const SUSPICIOUS_APK_KEYWORDS = [
    'free', 'unlimited', 'mod', 'hack', 'crack', 'generator', 'gems', 'cheats',
    'pro', 'premium', 'update', 'patch', 'vip', 'gold', 'spy', 'tracker'
];

const HIGH_PROFILE_APP_NAMESPACES = {
    'whatsapp': 'com.whatsapp',
    'instagram': 'com.instagram.android',
    'facebook': 'com.facebook.katana',
    'telegram': 'org.telegram.messenger',
    'youtube': 'com.google.android.youtube',
    'netflix': 'com.netflix.mediaclient',
    'spotify': 'com.spotify.music',
    'paytm': 'net.one97.paytm',
    'googlepay': 'com.google.android.apps.nbu.paisa.user',
    'phonepe': 'com.phonepe.app',
    'snapchat': 'com.snapchat.android',
    'tiktok': 'com.zhiliaoapp.musically'
};

export function analyzeApkPackageStructure(pkgName) {
    if (!pkgName || typeof pkgName !== 'string') {
        return { isValidFormat: false, indicators: [], riskPoints: 0 };
    }

    const clean = pkgName.trim().toLowerCase();
    const parts = clean.split('.').filter(Boolean);
    const indicators = [];
    let riskPoints = 0;

    // 1. Android Reverse-Domain Naming Standard Validation (e.g. com.company.app)
    const isValidJavaPackage = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/i.test(clean);
    if (!isValidJavaPackage) {
        indicators.push({
            id: 'INVALID_PACKAGE_NAMESPACE_SYNTAX',
            category: 'Package Structure',
            severity: 'warning',
            title: 'Irregular Android Package Naming Syntax',
            description: `"${clean}" does not adhere to standard Android Java reverse-DNS naming conventions (e.g., com.example.app).`
        });
        riskPoints += 20;
    }

    // 2. High-Profile App Masquerading / Suffix Hijacking
    for (const [brand, officialPkg] of Object.entries(HIGH_PROFILE_APP_NAMESPACES)) {
        if (clean.includes(brand) && clean !== officialPkg) {
            const isOfficialSub = clean.startsWith(officialPkg) && !clean.includes('free') && !clean.includes('update') && !clean.includes('mod');
            if (!isOfficialSub) {
                indicators.push({
                    id: 'OFFICIAL_APP_SHADOWING',
                    category: 'Brand & Identity',
                    severity: 'danger',
                    title: `Impersonation of Official "${brand.toUpperCase()}" Package`,
                    description: `Package "${clean}" masquerades as the official application (Official ID: "${officialPkg}"). Trojanized APKs frequently append deceptive keywords to legitimate brand namespaces.`
                });
                riskPoints += 45;
                break;
            }
        }
    }

    // 3. Android System Namespace Mimicry (e.g. com.android.system.service.update)
    if (clean.startsWith('com.android.') || clean.startsWith('com.google.android.')) {
        const legitimateGooglePackages = [
            'com.google.android.youtube', 'com.google.android.gm', 'com.google.android.apps.maps',
            'com.google.android.googlequicksearchbox', 'com.google.android.apps.photos',
            'com.google.android.inputmethod.latin', 'com.google.android.gms'
        ];
        if (!legitimateGooglePackages.includes(clean)) {
            indicators.push({
                id: 'FAKE_SYSTEM_PACKAGE_MIMICRY',
                category: 'Privilege & Identity',
                severity: 'danger',
                title: 'Core Android / Google System Service Masquerade',
                description: `Package claims "com.android.*" or "com.google.android.*" system namespace ("${clean}"). Malware developers use fake OS namespaces to mislead users into granting device administrator or accessibility permissions.`
            });
            riskPoints += 40;
        }
    }

    // 4. Modded / Hack / Generator Keyword Suffixes
    const matchedKeywords = SUSPICIOUS_APK_KEYWORDS.filter(kw => parts.includes(kw) || clean.includes(`.${kw}.`) || clean.endsWith(`.${kw}`));
    if (matchedKeywords.length > 0) {
        const points = matchedKeywords.length >= 3 ? 65 : matchedKeywords.length >= 2 ? 50 : 35;
        indicators.push({
            id: 'MOD_HACK_FRAUD_KEYWORDS',
            category: 'Payload Characteristics',
            severity: 'danger',
            title: 'Modded / Crack / Currency Generator Lure in Package ID',
            description: `Package contains deceptive high-risk tokens: [${matchedKeywords.join(', ')}]. Widely used to distribute banking trojans (e.g. Anatsa, TeaBot, SharkBot) disguised as game mods or cracked utilities.`
        });
        riskPoints += points;
    }

    return {
        isValidFormat: isValidJavaPackage,
        packageParts: parts,
        indicators,
        riskPoints
    };
}

