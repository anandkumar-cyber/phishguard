/**
 * Typosquatting & Brand Impersonation Analyzer
 * Computes normalized Levenshtein distance and character substitution heuristics against known high-value targets.
 */

import { TARGET_BRANDS, BRAND_SLUGS } from '../data/brands.js';

export function computeLevenshteinDistance(a, b) {
    if (!a || !b) return (a || b || '').length;
    const m = a.length;
    const n = b.length;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            if (a[i - 1] === b[j - 1]) {
                dp[i][j] = dp[i - 1][j - 1];
            } else {
                dp[i][j] = 1 + Math.min(
                    dp[i - 1][j],     // deletion
                    dp[i][j - 1],     // insertion
                    dp[i - 1][j - 1]  // substitution
                );
            }
        }
    }

    return dp[m][n];
}

/**
 * Normalizes common visual character substitutions (leetspeak / typosquatting tricks)
 */
export function normalizeSubstitutions(str) {
    if (!str) return '';
    return str.toLowerCase()
        .replace(/0/g, 'o')
        .replace(/1/g, 'l')
        .replace(/3/g, 'e')
        .replace(/4/g, 'a')
        .replace(/5/g, 's')
        .replace(/8/g, 'b')
        .replace(/vv/g, 'w')
        .replace(/rn/g, 'm')
        .replace(/cl/g, 'd');
}

/**
 * Analyzes a domain name for brand typosquatting, combosquatting, or subdomain shadowing.
 */
export function analyzeTyposquatting(hostname, brands = TARGET_BRANDS) {
    if (!hostname || typeof hostname !== 'string') {
        return { isTyposquatted: false, matchedBrand: null, distance: -1, type: null, details: null };
    }

    const cleanHost = hostname.toLowerCase().trim();
    const parts = cleanHost.split('.').filter(Boolean);
    if (parts.length === 0) return { isTyposquatted: false };

    // Check if the entire hostname matches a legitimate canonical domain
    for (const brandObj of brands) {
        if (brandObj.canonicalDomains.includes(cleanHost)) {
            return { isTyposquatted: false, matchedBrand: null, distance: 0, type: 'canonical_brand_domain', details: null };
        }
    }

    // Identify registered domain vs subdomains
    const tld = parts.slice(-1)[0];
    const sld = parts.length > 1 ? parts[parts.length - 2] : parts[0];
    const subdomains = parts.length > 2 ? parts.slice(0, parts.length - 2).join('.') : '';

    // Check 1: Subdomain Brand Shadowing (e.g. paypal.com.account-verify.ru)
    for (const brandObj of brands) {
        const brand = brandObj.slug;
        if (subdomains.includes(brand)) {
            // If the actual SLD is NOT the legitimate brand domain
            if (sld !== brand && !brandObj.canonicalDomains.some(d => d.includes(sld))) {
                return {
                    isTyposquatted: true,
                    matchedBrand: brandObj.name,
                    distance: 0,
                    type: 'subdomain_shadowing',
                    details: `Brand "${brandObj.name}" appears prepended in subdomain "${subdomains}", masquerading under root domain "${sld}.${tld}".`
                };
            }
        }
    }

    // If SLD is an exact legitimate brand name, do not flag cross-brand typosquatting (e.g. github.com vs gitlab.com)
    if (BRAND_SLUGS.includes(sld)) {
        return { isTyposquatted: false, matchedBrand: null, distance: -1, type: null, details: null };
    }

    const normalizedSld = normalizeSubstitutions(sld);
    const sldCleanWithoutHyphens = sld.replace(/[-_]/g, '');
    const normCleanWithoutHyphens = normalizedSld.replace(/[-_]/g, '');

    for (const brandObj of brands) {
        const brand = brandObj.slug;

        // Check exact normalized match (e.g. paypa1 -> paypal, micros0ft -> microsoft)
        if (normCleanWithoutHyphens === brand && sldCleanWithoutHyphens !== brand) {
            return {
                isTyposquatted: true,
                matchedBrand: brandObj.name,
                distance: 1,
                type: 'character_substitution',
                details: `Lookalike character substitution detected: "${sld}" mimics official brand "${brandObj.name}".`
            };
        }

        // Combosquatting: brand embedded with security/login words (e.g. paypa1-security, paypal-login)
        if (
            (normCleanWithoutHyphens.includes(brand) && normCleanWithoutHyphens !== brand) ||
            sld.includes(`${brand}-`) || sld.includes(`-${brand}`) ||
            normalizedSld.includes(`${brand}-`) || normalizedSld.includes(`-${brand}`)
        ) {
            return {
                isTyposquatted: true,
                matchedBrand: brandObj.name,
                distance: 0,
                type: 'combosquatting',
                details: `Combosquatting pattern detected: "${sld}" pairs brand name "${brandObj.name}" with deceptive operational keywords.`
            };
        }

        // Levenshtein distance check on isolated SLD
        const dist = computeLevenshteinDistance(sldCleanWithoutHyphens, brand);
        if (brand.length >= 4 && dist <= 2 && dist > 0) {
            const lenRatio = Math.abs(sldCleanWithoutHyphens.length - brand.length);
            if (lenRatio <= 2) {
                return {
                    isTyposquatted: true,
                    matchedBrand: brandObj.name,
                    distance: dist,
                    type: 'edit_distance_variation',
                    details: `Potential brand typosquatting: "${sld}" has a Levenshtein distance of ${dist} from "${brandObj.name}".`
                };
            }
        }
    }

    return {
        isTyposquatted: false,
        matchedBrand: null,
        distance: -1,
        type: null,
        details: null
    };
}

