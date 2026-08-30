/**
 * Comprehensive Deterministic URL Security Analyzer
 * Integrates RFC 3986 parsing, Shannon entropy, brand typosquatting, homoglyphs, TLD risk profiling, and lexical vectors.
 */

import { evaluateDomainEntropy } from './entropy.js';
import { analyzeTyposquatting } from './typosquatting.js';
import { analyzeHomoglyphs } from './homoglyph.js';
import { analyzeTld } from './tldAnalyzer.js';
import { analyzeLexicalVectors } from './lexicalAnalyzer.js';

export function analyzeUrl(rawInput) {
    if (!rawInput || typeof rawInput !== 'string' || rawInput.trim() === '') {
        return {
            isValid: false,
            error: 'Empty or missing URL string',
            indicators: [],
            riskScore: 0
        };
    }

    let input = rawInput.trim();
    let hasExplicitScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(input);
    let parseCandidate = hasExplicitScheme ? input : `http://${input}`;

    let parsed;
    try {
        parsed = new URL(parseCandidate);
    } catch (e) {
        return {
            isValid: false,
            error: `Malformed URL structure: unable to parse "${input}".`,
            indicators: [{
                id: 'MALFORMED_URL_SYNTAX',
                category: 'Syntax & Structure',
                severity: 'danger',
                title: 'Invalid or Malformed URL Syntax',
                description: 'The supplied input violates standard URI format conventions (RFC 3986).'
            }],
            riskScore: 30
        };
    }

    const hostname = parsed.hostname || '';
    const indicators = [];
    let totalRiskPoints = 0;

    // 1. Homoglyph and Punycode Analysis
    const homoglyphResult = analyzeHomoglyphs(hostname);
    if (homoglyphResult.isHomoglyph) {
        indicators.push({
            id: 'HOMOGLYPH_IDN_SPOOFING',
            category: 'Identity & Brand',
            severity: 'danger',
            title: homoglyphResult.isPunycode ? 'Punycode / IDN Domain Detected' : 'Internationalized Homoglyph Attack',
            description: homoglyphResult.details
        });
        totalRiskPoints += 35;
    }

    // 2. Typosquatting and Brand Impersonation Analysis
    const typosquatResult = analyzeTyposquatting(hostname);
    if (typosquatResult.isTyposquatted) {
        indicators.push({
            id: 'BRAND_TYPOSQUATTING_DETECTED',
            category: 'Identity & Brand',
            severity: 'danger',
            title: `Potential Impersonation of Brand: "${typosquatResult.matchedBrand.toUpperCase()}"`,
            description: typosquatResult.details
        });
        totalRiskPoints += 40;
    }

    // 3. Shannon Domain Entropy Analysis
    const entropyResult = evaluateDomainEntropy(hostname);
    if (entropyResult.isHighEntropy) {
        indicators.push({
            id: 'HIGH_DOMAIN_ENTROPY',
            category: 'Domain & Host',
            severity: 'warning',
            title: 'Algorithmic or Random Domain Generation (High Entropy)',
            description: entropyResult.explanation
        });
        totalRiskPoints += 20;
    }

    // 4. TLD Risk Categorization
    const tldResult = analyzeTld(hostname);
    if (tldResult.riskLevel === 'elevated') {
        indicators.push({
            id: 'ELEVATED_RISK_TLD',
            category: 'Domain & Host',
            severity: 'warning',
            title: `Elevated-Risk Top-Level Domain (${tldResult.tld})`,
            description: tldResult.explanation
        });
        totalRiskPoints += tldResult.scoreModifier;
    } else if (tldResult.riskLevel === 'high_trust') {
        indicators.push({
            id: 'HIGH_TRUST_TLD',
            category: 'Domain & Host',
            severity: 'info',
            title: `High-Trust Official TLD (${tldResult.tld})`,
            description: tldResult.explanation
        });
        totalRiskPoints += tldResult.scoreModifier;
    }

    // 5. Lexical & Structural Vectors
    const lexicalResult = analyzeLexicalVectors(parsed, input);
    indicators.push(...lexicalResult.indicators);
    totalRiskPoints += lexicalResult.riskPoints;

    const normalizedScore = Math.max(0, Math.min(100, Math.round(totalRiskPoints)));

    return {
        isValid: true,
        artifactType: 'url',
        input,
        parsedAnatomy: {
            protocol: parsed.protocol,
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
            pathname: parsed.pathname,
            search: parsed.search,
            hash: parsed.hash,
            tld: tldResult.tld,
            entropy: entropyResult.entropy,
            isIpAddress: /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)
        },
        indicators,
        rawRiskPoints: totalRiskPoints,
        calculatedScore: normalizedScore
    };
}

