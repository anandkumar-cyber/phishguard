/**
 * Threat Severity Definitions & Verdict Thresholds
 */

export const VERDICT_THRESHOLDS = {
    SAFE: { min: 0, max: 24, label: 'SAFE', color: 'emerald', key: 'safe' },
    SUSPICIOUS: { min: 25, max: 59, label: 'SUSPICIOUS', color: 'amber', key: 'suspicious' },
    HIGH_RISK: { min: 60, max: 84, label: 'HIGH RISK', color: 'crimson', key: 'high_risk' },
    MALICIOUS: { min: 85, max: 100, label: 'MALICIOUS', color: 'crimson', key: 'malicious' }
};

export function getVerdictFromScore(score) {
    const s = Math.max(0, Math.min(100, Math.round(score || 0)));
    
    if (s <= 24) return VERDICT_THRESHOLDS.SAFE;
    if (s <= 59) return VERDICT_THRESHOLDS.SUSPICIOUS;
    if (s <= 84) return VERDICT_THRESHOLDS.HIGH_RISK;
    return VERDICT_THRESHOLDS.MALICIOUS;
}

export function calculateConfidence(indicatorCount, hasAiAnalysis = false) {
    let baseConfidence = 70;
    if (indicatorCount >= 3) baseConfidence += 15;
    else if (indicatorCount >= 1) baseConfidence += 10;
    if (hasAiAnalysis) baseConfidence += 10;
    return Math.min(98, baseConfidence);
}

