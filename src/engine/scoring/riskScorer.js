/**
 * Transparent Multi-Factor Threat Scorer & Matrix Generator
 */

import { getVerdictFromScore, calculateConfidence } from './severity.js';

export function buildThreatReport({ deterministicResult, aiResult = null, artifactType = 'url' }) {
    const indicators = [...(deterministicResult.indicators || [])];
    let score = deterministicResult.calculatedScore || 0;
    const isAiUsed = Boolean(aiResult && aiResult.success && aiResult.data);

    let aiSummary = null;
    let aiRecommendation = null;

    if (isAiUsed) {
        const aiScore = Number(aiResult.data.risk_score);
        if (!isNaN(aiScore)) {
            // Weighted average: 60% deterministic rule vectors + 40% AI semantic context
            score = Math.round((score * 0.60) + (aiScore * 0.40));
        }

        if (aiResult.data.summary) {
            aiSummary = aiResult.data.summary;
        }
        if (aiResult.data.recommendation) {
            aiRecommendation = aiResult.data.recommendation;
        }

        if (Array.isArray(aiResult.data.flags)) {
            for (const f of aiResult.data.flags) {
                if (f && f.text && !indicators.some(i => i.title.toLowerCase().includes(f.text.toLowerCase().slice(0, 15)))) {
                    indicators.push({
                        id: 'AI_CONTEXT_OBSERVATION',
                        category: 'AI Context Matrix',
                        severity: f.level === 'danger' ? 'danger' : f.level === 'warning' ? 'warning' : 'info',
                        title: f.text,
                        description: 'Identified via Gemini 2.5 Flash threat intelligence matrix.'
                    });
                }
            }
        }
    }

    score = Math.max(0, Math.min(100, score));
    const verdictInfo = getVerdictFromScore(score);
    const confidence = calculateConfidence(indicators.length, isAiUsed);

    // Build "Why?" Key Reasons list (top 4 highest severity indicators)
    const whyReasons = indicators
        .sort((a, b) => {
            const weight = { danger: 3, warning: 2, info: 1 };
            return (weight[b.severity] || 0) - (weight[a.severity] || 0);
        })
        .slice(0, 4)
        .map(i => ({
            title: i.title,
            severity: i.severity,
            category: i.category
        }));

    if (whyReasons.length === 0) {
        whyReasons.push({
            title: 'No known phishing vectors, homoglyphs, or suspicious lexical lures detected',
            severity: 'info',
            category: 'Integrity Check'
        });
    }

    // Build Threat Matrix (Grouped by Category)
    const matrixCategories = [
        'Identity & Brand',
        'Domain & Host',
        'Lexical Analysis',
        'Social Engineering',
        'Obfuscation',
        'Transport & Routing',
        'Payload Characteristics',
        'Package Structure'
    ];

    const threatMatrix = matrixCategories
        .map(cat => {
            const catIndicators = indicators.filter(i => i.category === cat);
            if (catIndicators.length === 0) return null;
            const hasDanger = catIndicators.some(i => i.severity === 'danger');
            const hasWarning = catIndicators.some(i => i.severity === 'warning');
            const status = hasDanger ? 'CRITICAL' : hasWarning ? 'ELEVATED' : 'INFORMATIONAL';
            const statusColor = hasDanger ? 'crimson' : hasWarning ? 'amber' : 'cyan';

            return {
                category: cat,
                status,
                statusColor,
                count: catIndicators.length,
                details: catIndicators.map(i => i.title).join(', ')
            };
        })
        .filter(Boolean);

    let defaultRecommendation = 'Artifact appears consistent with normal usage. Always verify the address bar before entering credentials.';
    if (verdictInfo.key === 'malicious' || verdictInfo.key === 'high_risk') {
        defaultRecommendation = 'CRITICAL: Do not interact, click, or enter passwords/OTP. If accessed from an organization endpoint, report immediately to your SOC / IT Security team and purge the message.';
    } else if (verdictInfo.key === 'suspicious') {
        defaultRecommendation = 'CAUTION: Exercise elevated vigilance. Manually navigate to the verified official portal rather than clicking embedded links. Do not provide two-factor passcodes.';
    }

    const finalRecommendation = aiRecommendation || defaultRecommendation;
    const finalSummary = aiSummary || (
        score >= 60 
            ? `Threat matrix indicates significant risk (${score}/100) across ${indicators.length} identified vector(s). High likelihood of deceptive intent or credential harvesting.`
            : score >= 25
                ? `Artifact exhibits several suspicious characteristics (${score}/100). Exercise caution and independently verify the source.`
                : `Artifact passed all deterministic heuristic checks (${score}/100) with no active threat indicators identified.`
    );

    return {
        id: `PG-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`,
        timestamp: new Date().toISOString(),
        artifactType,
        input: deterministicResult.input,
        riskScore: score,
        verdict: verdictInfo.label,
        verdictKey: verdictInfo.key,
        verdictColor: verdictInfo.color,
        confidence: `${confidence}%`,
        summary: finalSummary,
        recommendation: finalRecommendation,
        whyReasons,
        indicators,
        threatMatrix,
        parsedAnatomy: deterministicResult.parsedAnatomy || null,
        engineInfo: {
            deterministic: true,
            aiAssisted: Boolean(isAiUsed),
            aiEngine: isAiUsed ? 'Gemini 2.5 Flash' : 'Offline Heuristic Engine'
        }
    };
}

