/**
 * Comprehensive Unit & Security Test Suite for PhishGuard Threat Engine
 * Evaluates 60+ targeted assertions across heuristics, scoring boundaries, AI validation, and security regressions.
 */

import { heuristicEngine } from '../src/engine/HeuristicEngine.js';
import { calculateShannonEntropy } from '../src/engine/url/entropy.js';
import { analyzeTyposquatting, computeLevenshteinDistance } from '../src/engine/url/typosquatting.js';
import { analyzeHomoglyphs } from '../src/engine/url/homoglyph.js';
import { analyzeTld } from '../src/engine/url/tldAnalyzer.js';
import { getVerdictFromScore } from '../src/engine/scoring/severity.js';
import { aiThreatService } from '../src/services/AiThreatService.js';
import { escapeHtml, sanitizeUrl } from '../src/utils/sanitization.js';
import { TEST_VECTORS } from './testVectors.js';

export function runEngineTests() {
    const results = {
        total: 0,
        passed: 0,
        failed: 0,
        details: []
    };

    function assert(condition, testName, message = '') {
        results.total++;
        if (condition) {
            results.passed++;
            results.details.push({ status: 'PASS', name: testName });
        } else {
            results.failed++;
            results.details.push({ status: 'FAIL', name: testName, message });
            console.error(`❌ FAIL: ${testName} - ${message}`);
        }
    }

    // =========================================================================
    // 1. URL ANALYSIS TESTS (BENIGN & ADVERSARIAL)
    // =========================================================================
    for (const vector of TEST_VECTORS.urls) {
        const analysis = heuristicEngine.analyze(vector.input, 'url');
        const report = heuristicEngine.generateReport(analysis, null, 'url');

        assert(
            vector.expectedVerdict.includes(report.verdictKey.toUpperCase()) || vector.expectedVerdict.includes(report.verdict.replace(/\s+/g, '_')),
            `URL Verdict for "${vector.input.slice(0, 35)}..."`,
            `Expected one of [${vector.expectedVerdict.join(', ')}], got "${report.verdict}" (Score: ${report.riskScore})`
        );

        if (vector.shouldTrigger) {
            for (const expectedId of vector.shouldTrigger) {
                const found = report.indicators.some(i => i.id === expectedId);
                assert(found, `URL Trigger "${expectedId}" for "${vector.input.slice(0, 30)}..."`, `Expected indicator ID "${expectedId}" to be detected`);
            }
        }

        if (vector.shouldNotTrigger) {
            for (const unwantedId of vector.shouldNotTrigger) {
                const found = report.indicators.some(i => i.id === unwantedId);
                assert(!found, `URL Clean of "${unwantedId}" for "${vector.input}"`, `Indicator "${unwantedId}" should not trigger on benign input`);
            }
        }
    }

    // =========================================================================
    // 2. MESSAGE & SMS TESTS (BENIGN & ADVERSARIAL)
    // =========================================================================
    for (const vector of TEST_VECTORS.messages) {
        const analysis = heuristicEngine.analyze(vector.input, 'message');
        const report = heuristicEngine.generateReport(analysis, null, 'message');

        assert(
            vector.expectedVerdict.includes(report.verdictKey.toUpperCase()) || vector.expectedVerdict.includes(report.verdict.replace(/\s+/g, '_')),
            `Message Verdict for "${vector.input.slice(0, 30)}..."`,
            `Expected one of [${vector.expectedVerdict.join(', ')}], got "${report.verdict}" (Score: ${report.riskScore})`
        );

        if (vector.shouldTrigger) {
            for (const expectedId of vector.shouldTrigger) {
                const found = report.indicators.some(i => i.id === expectedId);
                assert(found, `Message Trigger "${expectedId}"`, `Expected indicator ID "${expectedId}" to be detected`);
            }
        }

        if (vector.shouldNotTrigger) {
            for (const unwantedId of vector.shouldNotTrigger) {
                const found = report.indicators.some(i => i.id === unwantedId);
                assert(!found, `Message Clean of "${unwantedId}"`, `Indicator "${unwantedId}" should not trigger`);
            }
        }
    }

    // =========================================================================
    // 3. EMAIL ANALYSIS TESTS
    // =========================================================================
    for (const vector of TEST_VECTORS.emails) {
        const analysis = heuristicEngine.analyze(vector.input, 'email');
        const report = heuristicEngine.generateReport(analysis, null, 'email');

        assert(
            vector.expectedVerdict.includes(report.verdictKey.toUpperCase()) || vector.expectedVerdict.includes(report.verdict.replace(/\s+/g, '_')),
            `Email Verdict for "${vector.input.slice(0, 30)}..."`,
            `Expected one of [${vector.expectedVerdict.join(', ')}], got "${report.verdict}" (Score: ${report.riskScore})`
        );

        if (vector.shouldTrigger) {
            for (const expectedId of vector.shouldTrigger) {
                const found = report.indicators.some(i => i.id === expectedId);
                assert(found, `Email Trigger "${expectedId}"`, `Expected indicator ID "${expectedId}" to be detected`);
            }
        }

        if (vector.shouldNotTrigger) {
            for (const unwantedId of vector.shouldNotTrigger) {
                const found = report.indicators.some(i => i.id === unwantedId);
                assert(!found, `Email Clean of "${unwantedId}"`, `Indicator "${unwantedId}" should not trigger`);
            }
        }
    }

    // =========================================================================
    // 4. APK PACKAGE ANALYSIS TESTS
    // =========================================================================
    for (const vector of TEST_VECTORS.apks) {
        const analysis = heuristicEngine.analyze(vector.input, 'apk');
        const report = heuristicEngine.generateReport(analysis, null, 'apk');

        assert(
            vector.expectedVerdict.includes(report.verdictKey.toUpperCase()) || vector.expectedVerdict.includes(report.verdict.replace(/\s+/g, '_')),
            `APK Verdict for "${vector.input}"`,
            `Expected one of [${vector.expectedVerdict.join(', ')}], got "${report.verdict}" (Score: ${report.riskScore})`
        );

        if (vector.shouldTrigger) {
            for (const expectedId of vector.shouldTrigger) {
                const found = report.indicators.some(i => i.id === expectedId);
                assert(found, `APK Trigger "${expectedId}"`, `Expected indicator ID "${expectedId}" to be detected`);
            }
        }

        if (vector.shouldNotTrigger) {
            for (const unwantedId of vector.shouldNotTrigger) {
                const found = report.indicators.some(i => i.id === unwantedId);
                assert(!found, `APK Clean of "${unwantedId}"`, `Indicator "${unwantedId}" should not trigger`);
            }
        }
    }

    // =========================================================================
    // 5. MATHEMATICAL & ALGORITHMIC UNIT TESTS
    // =========================================================================
    // Shannon Entropy
    assert(calculateShannonEntropy('aaaa') === 0, 'Shannon Entropy of uniform string ("aaaa") is 0', 'Uniform string must have zero entropy');
    assert(calculateShannonEntropy('abcdefgh') > 2.8, 'Shannon Entropy of diverse string is high', 'Diverse string should have high entropy');
    assert(calculateShannonEntropy('') === 0, 'Shannon Entropy of empty string is 0', 'Empty string must return 0');

    // Levenshtein Distance
    assert(computeLevenshteinDistance('paypal', 'paypa1') === 1, 'Levenshtein distance("paypal", "paypa1") === 1');
    assert(computeLevenshteinDistance('google', 'goog1e') === 1, 'Levenshtein distance("google", "goog1e") === 1');
    assert(computeLevenshteinDistance('same', 'same') === 0, 'Levenshtein distance identical strings === 0');

    // Homoglyphs
    const homoglyphTest = analyzeHomoglyphs('xn--pple-43d.com');
    assert(homoglyphTest.isHomoglyph && homoglyphTest.isPunycode, 'Punycode detected for xn--pple-43d.com');

    const cleanLatinTest = analyzeHomoglyphs('paypal.com');
    assert(!cleanLatinTest.isHomoglyph, 'Clean Latin domain not flagged as homoglyph');

    // TLD Risk
    const highRiskTld = analyzeTld('phish-portal.xyz');
    assert(highRiskTld.riskLevel === 'elevated' && highRiskTld.scoreModifier > 0, '.xyz flagged as elevated-risk TLD');

    const govTld = analyzeTld('agency.gov');
    assert(govTld.riskLevel === 'high_trust' && govTld.scoreModifier < 0, '.gov identified as high-trust TLD with negative risk score modifier');

    // =========================================================================
    // 6. SCORING & VERDICT THRESHOLD TESTS
    // =========================================================================
    assert(getVerdictFromScore(0).label === 'SAFE', 'Score 0 produces SAFE verdict');
    assert(getVerdictFromScore(24).label === 'SAFE', 'Score 24 produces SAFE verdict');
    assert(getVerdictFromScore(25).label === 'SUSPICIOUS', 'Score 25 produces SUSPICIOUS verdict');
    assert(getVerdictFromScore(59).label === 'SUSPICIOUS', 'Score 59 produces SUSPICIOUS verdict');
    assert(getVerdictFromScore(60).label === 'HIGH RISK', 'Score 60 produces HIGH RISK verdict');
    assert(getVerdictFromScore(84).label === 'HIGH RISK', 'Score 84 produces HIGH RISK verdict');
    assert(getVerdictFromScore(85).label === 'MALICIOUS', 'Score 85 produces MALICIOUS verdict');
    assert(getVerdictFromScore(100).label === 'MALICIOUS', 'Score 100 produces MALICIOUS verdict');
    assert(getVerdictFromScore(-10).label === 'SAFE', 'Negative score clamped to SAFE');
    assert(getVerdictFromScore(150).label === 'MALICIOUS', 'Overflow score clamped to MALICIOUS');

    // =========================================================================
    // 7. AI RESPONSE VALIDATION & SANITIZATION TESTS
    // =========================================================================
    const oversizedAiResponse = {
        verdict: 'MALICIOUS',
        risk_score: 999999, // Intentional out-of-bounds score
        summary: 'Dangerous domain.',
        flags: [{ level: 'danger', text: 'Suspicious domain' }],
        recommendation: 'Block immediately.'
    };
    const sanitizedAi = aiThreatService.validateAndSanitizeOutput(oversizedAiResponse);
    assert(sanitizedAi && sanitizedAi.risk_score === 100, 'AI response oversized score (999999) clamped to 100');

    const invalidVerdictAiResponse = {
        verdict: 'UNKNOWN_CUSTOM_ENUM',
        risk_score: 80,
        summary: 'Risk detected.',
        flags: [],
        recommendation: 'Review.'
    };
    const sanitizedVerdict = aiThreatService.validateAndSanitizeOutput(invalidVerdictAiResponse);
    assert(sanitizedVerdict && sanitizedVerdict.verdict === 'HIGH_RISK', 'Invalid AI verdict mapped correctly from score threshold');

    assert(aiThreatService.validateAndSanitizeOutput(null) === null, 'Null AI response rejected safely');
    assert(aiThreatService.validateAndSanitizeOutput('not a json object') === null, 'String AI response rejected safely');

    // =========================================================================
    // 8. SECURITY REGRESSION & XSS DEFENSE TESTS
    // =========================================================================
    const xssPayload = '<script>alert("xss")</script><img src=x onerror=alert(1)>';
    const escaped = escapeHtml(xssPayload);
    assert(!escaped.includes('<') && !escaped.includes('>') && !escaped.includes('"'), 'HTML special characters (<, >, ") escaped safely');

    const dangerousUrl = 'javascript:alert(document.cookie)';
    const sanitizedLink = sanitizeUrl(dangerousUrl);
    assert(sanitizedLink === '#unsafe-protocol-blocked', 'javascript: URI scheme neutralized safely');

    const dataUri = 'data:text/html,<script>alert(1)</script>';
    assert(sanitizeUrl(dataUri) === '#unsafe-protocol-blocked', 'data: URI scheme neutralized safely');

    // Malformed URL resilience
    const malformedResult = heuristicEngine.analyze(':::not-a-valid-url:::', 'url');
    assert(malformedResult.isValid === false, 'Malformed URL does not throw uncaught exception and returns valid: false');

    return results;
}
