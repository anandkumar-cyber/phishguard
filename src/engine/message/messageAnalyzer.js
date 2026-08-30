/**
 * Master Message & Email Heuristic Security Analyzer
 * Evaluates raw SMS texts and Email content, parses embedded URLs, checks sender masquerade, and scores social engineering indicators.
 */

import { analyzeUrgencyPatterns } from './urgencyAnalyzer.js';
import { analyzeSocialEngineering } from './socialEngineering.js';
import { analyzeUrl } from '../url/urlAnalyzer.js';
import { analyzeTld } from '../url/tldAnalyzer.js';

const URL_EXTRACT_REGEX = /(https?:\/\/[^\s<>"'()]+|www\.[^\s<>"'()]+|[a-zA-Z0-9-]+\.(?:ru|xyz|top|tk|ml|ga|cf|gq|buzz|click|online|site|live|info|club|work|vip)[^\s<>"'()]*)/gi;

export function analyzeMessage(rawInput, isEmail = false) {
    if (!rawInput || typeof rawInput !== 'string' || rawInput.trim() === '') {
        return {
            isValid: false,
            error: 'Empty or missing message payload',
            indicators: [],
            riskScore: 0
        };
    }

    const text = rawInput.trim();
    const indicators = [];
    let totalRisk = 0;

    // 1. Urgency & Coercion Patterns
    const urgencyResult = analyzeUrgencyPatterns(text);
    indicators.push(...urgencyResult.indicators);
    totalRisk += urgencyResult.score;

    // 2. Social Engineering & Vector Classification
    const socEngResult = analyzeSocialEngineering(text);
    indicators.push(...socEngResult.indicators);
    totalRisk += socEngResult.score;

    // 3. Embedded Link Extraction & Nested URL Heuristics
    const extractedUrls = [];
    let match;
    while ((match = URL_EXTRACT_REGEX.exec(text)) !== null) {
        extractedUrls.push(match[0]);
    }

    const embeddedUrlAnalyses = [];
    if (extractedUrls.length > 0) {
        for (const urlStr of extractedUrls.slice(0, 3)) {
            const linkAnalysis = analyzeUrl(urlStr);
            embeddedUrlAnalyses.push({
                url: urlStr,
                score: linkAnalysis.calculatedScore,
                indicators: linkAnalysis.indicators
            });

            if (linkAnalysis.calculatedScore >= 40) {
                indicators.push({
                    id: 'EMBEDDED_SUSPICIOUS_LINK',
                    category: 'Embedded Links',
                    severity: linkAnalysis.calculatedScore >= 70 ? 'danger' : 'warning',
                    title: `Suspicious Embedded Link (${urlStr})`,
                    description: `The message contains an elevated-risk link "${urlStr}" (Risk Score: ${linkAnalysis.calculatedScore}/100) exhibiting: ${linkAnalysis.indicators.map(i => i.title).slice(0, 2).join('; ')}`
                });
                totalRisk += Math.round(linkAnalysis.calculatedScore * 0.5);
            }
        }
    } else {
        if (urgencyResult.score > 20) {
            indicators.push({
                id: 'URGENT_CALL_TO_ACTION_NO_OFFICIAL_URL',
                category: 'Communication Integrity',
                severity: 'info',
                title: 'High Urgency Without Verifiable Domain',
                description: 'The message demands urgent user action without providing an official verifiable channel or domain.'
            });
            totalRisk += 10;
        }
    }

    // 4. Email Specific Header & Display Name Spoofing
    if (isEmail) {
        const fromMatch = text.match(/from:\s*["']?([^<"'\n]+)["']?\s*<([^>]+)>/i);
        if (fromMatch) {
            const displayName = fromMatch[1].trim().toLowerCase();
            const actualEmail = fromMatch[2].trim().toLowerCase();
            const emailDomain = actualEmail.split('@')[1] || '';

            // Check TLD risk of sending address
            const senderTldResult = analyzeTld(emailDomain);
            if (senderTldResult.riskLevel === 'elevated') {
                indicators.push({
                    id: 'SENDER_ELEVATED_RISK_TLD',
                    category: 'Domain & Host',
                    severity: 'warning',
                    title: `Email Sender Domain Uses Elevated-Risk TLD (${senderTldResult.tld})`,
                    description: `The email originated from "${emailDomain}" carrying an elevated-risk registrar profile: ${senderTldResult.explanation}`
                });
                totalRisk += senderTldResult.scoreModifier;
            }

            const knownBrands = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'chase', 'bank of america', 'sbi', 'hdfc', 'ceo'];
            for (const brand of knownBrands) {
                if (displayName.includes(brand) && !emailDomain.includes(brand.replace(/\s+/g, ''))) {
                    indicators.push({
                        id: 'EMAIL_DISPLAY_NAME_SPOOFING',
                        category: 'Identity & Brand',
                        severity: 'danger',
                        title: `Email Display Name Spoofing ("${fromMatch[1]}")`,
                        description: `The sender display name claims to be "${fromMatch[1]}", but the sending address originates from an unrelated domain ("${emailDomain}"). A hallmark indicator of spear-phishing.`
                    });
                    totalRisk += 35;
                    break;
                }
            }
        }
    }

    const calculatedScore = Math.max(0, Math.min(100, Math.round(totalRisk)));

    return {
        isValid: true,
        artifactType: isEmail ? 'email' : 'message',
        input: text,
        extractedUrls,
        embeddedUrlAnalyses,
        indicators,
        rawRiskPoints: totalRisk,
        calculatedScore
    };
}

