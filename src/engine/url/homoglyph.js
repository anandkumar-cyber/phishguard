/**
 * Homoglyph & Punycode (IDN) Attack Detector
 * Identifies internationalized domain name (IDN) spoofing and mixed-script Cyrillic/Greek lookalikes.
 */

// Common Cyrillic & Greek homoglyphs that visually mimic Latin ASCII characters
const HOMOGLYPH_MAP = {
    // Cyrillic
    '\u0430': 'a', // Cyrillic Small Letter A
    '\u0441': 'c', // Cyrillic Small Letter Es
    '\u0434': 'd', // Cyrillic Small Letter De
    '\u0435': 'e', // Cyrillic Small Letter Ie
    '\u0456': 'i', // Cyrillic Small Letter Byelorussian-Ukrainian I
    '\u0458': 'j', // Cyrillic Small Letter Je
    '\u043A': 'k', // Cyrillic Small Letter Ka
    '\u043E': 'o', // Cyrillic Small Letter O
    '\u0440': 'p', // Cyrillic Small Letter Er
    '\u0445': 'x', // Cyrillic Small Letter Ha
    '\u0443': 'y', // Cyrillic Small Letter U
    '\u0455': 's', // Cyrillic Small Letter Dze
    // Greek
    '\u03B1': 'a', // Greek Small Letter Alpha
    '\u03BF': 'o', // Greek Small Letter Omicron
    '\u03BD': 'v', // Greek Small Letter Nu
    '\u03C1': 'p', // Greek Small Letter Rho
    '\u03C4': 't', // Greek Small Letter Tau
    '\u03B9': 'i'  // Greek Small Letter Iota
};

export function analyzeHomoglyphs(hostname) {
    if (!hostname || typeof hostname !== 'string') {
        return { isHomoglyph: false, isPunycode: false, details: null, unicodeDecoded: null };
    }

    const cleanHost = hostname.toLowerCase();

    // Check 1: Explicit Punycode notation (xn--)
    if (cleanHost.includes('xn--')) {
        return {
            isHomoglyph: true,
            isPunycode: true,
            details: `Punycode domain indicator ("xn--") detected. Punycode domains encode non-ASCII characters and are frequently used in homograph attacks to impersonate Latin domains.`,
            unicodeDecoded: cleanHost
        };
    }

    // Check 2: Direct Unicode non-ASCII lookalike characters in hostname
    const detectedHomoglyphs = [];
    let hasNonAscii = false;

    for (let i = 0; i < cleanHost.length; i++) {
        const char = cleanHost[i];
        const code = char.charCodeAt(0);
        
        if (code > 127) {
            hasNonAscii = true;
            if (HOMOGLYPH_MAP[char]) {
                detectedHomoglyphs.push({
                    char,
                    hex: `U+${code.toString(16).toUpperCase().padStart(4, '0')}`,
                    mimics: HOMOGLYPH_MAP[char]
                });
            }
        }
    }

    if (detectedHomoglyphs.length > 0) {
        const charDescriptions = detectedHomoglyphs
            .map(h => `'${h.char}' (${h.hex} mimicking Latin '${h.mimics}')`)
            .join(', ');
        return {
            isHomoglyph: true,
            isPunycode: false,
            details: `Mixed-script homoglyph attack detected: contains non-ASCII characters [${charDescriptions}] that visually imitate Latin letters.`,
            unicodeDecoded: cleanHost
        };
    }

    if (hasNonAscii) {
        return {
            isHomoglyph: true,
            isPunycode: false,
            details: `Hostname contains non-ASCII Unicode characters outside the standard Latin alphanumeric set.`,
            unicodeDecoded: cleanHost
        };
    }

    return {
        isHomoglyph: false,
        isPunycode: false,
        details: null,
        unicodeDecoded: null
    };
}

