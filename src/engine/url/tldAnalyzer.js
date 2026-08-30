/**
 * Top-Level Domain (TLD) Risk Analyzer
 * Categorizes TLD risk levels based on historical threat intelligence abuse rates without making false deterministic claims.
 */

import { TLD_RISK_REGISTRY, HIGH_TRUST_TLDS } from '../data/tldMetadata.js';

export function analyzeTld(hostname) {
    if (!hostname || typeof hostname !== 'string') {
        return { tld: '', riskLevel: 'neutral', scoreModifier: 0, explanation: 'No valid TLD detected.' };
    }

    const parts = hostname.toLowerCase().split('.').filter(Boolean);
    if (parts.length < 2) {
        return { tld: '', riskLevel: 'neutral', scoreModifier: 0, explanation: 'Local or unqualified hostname.' };
    }

    // Check multi-part TLDs first (e.g. .gov.in, .gov.uk, .co.uk)
    const twoPartTld = parts.slice(-2).join('.');
    if (HIGH_TRUST_TLDS[twoPartTld]) {
        return {
            tld: `.${twoPartTld}`,
            riskLevel: 'high_trust',
            scoreModifier: HIGH_TRUST_TLDS[twoPartTld].trustBonus,
            explanation: HIGH_TRUST_TLDS[twoPartTld].rationale
        };
    }

    const singleTld = parts[parts.length - 1];

    if (HIGH_TRUST_TLDS[singleTld]) {
        return {
            tld: `.${singleTld}`,
            riskLevel: 'high_trust',
            scoreModifier: HIGH_TRUST_TLDS[singleTld].trustBonus,
            explanation: HIGH_TRUST_TLDS[singleTld].rationale
        };
    }

    if (TLD_RISK_REGISTRY[singleTld]) {
        return {
            tld: `.${singleTld}`,
            riskLevel: 'elevated',
            scoreModifier: TLD_RISK_REGISTRY[singleTld].score,
            explanation: `.${singleTld} carries an elevated-risk registration profile: ${TLD_RISK_REGISTRY[singleTld].rationale}`
        };
    }

    return {
        tld: `.${singleTld}`,
        riskLevel: 'standard',
        scoreModifier: 0,
        explanation: `Standard generic or country-code TLD (.${singleTld}).`
    };
}

