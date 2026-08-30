/**
 * Real-Time Session Telemetry & Threat Analytics Engine
 * Computes genuine metrics solely from user scan history. Zero mock statistics.
 */

export class AnalyticsEngine {
    static computeMetrics(history = []) {
        if (!Array.isArray(history) || history.length === 0) {
            return {
                hasData: false,
                totalScans: 0,
                threatsDetected: 0,
                suspiciousCount: 0,
                safeCount: 0,
                averageRisk: 0,
                verdictDistribution: { safe: 0, suspicious: 0, highRisk: 0, malicious: 0 },
                artifactDistribution: { url: 0, message: 0, email: 0, apk: 0 },
                topAttackVectors: []
            };
        }

        const totalScans = history.length;
        let sumRisk = 0;
        let safeCount = 0;
        let suspiciousCount = 0;
        let highRiskCount = 0;
        let maliciousCount = 0;

        const artifactCounts = { url: 0, message: 0, email: 0, apk: 0 };
        const vectorFrequencies = {};

        for (const scan of history) {
            const score = Number(scan.riskScore) || 0;
            sumRisk += score;

            const verdict = (scan.verdict || '').toUpperCase();
            if (verdict === 'SAFE') safeCount++;
            else if (verdict === 'SUSPICIOUS') suspiciousCount++;
            else if (verdict === 'HIGH RISK' || verdict === 'HIGH_RISK') highRiskCount++;
            else if (verdict === 'MALICIOUS' || verdict === 'PHISHING') maliciousCount++;
            else suspiciousCount++;

            const type = (scan.artifactType || 'url').toLowerCase();
            if (artifactCounts[type] !== undefined) {
                artifactCounts[type]++;
            } else {
                artifactCounts.url++;
            }

            if (Array.isArray(scan.indicators)) {
                for (const ind of scan.indicators) {
                    const cat = ind.category || 'General';
                    vectorFrequencies[cat] = (vectorFrequencies[cat] || 0) + 1;
                }
            }
        }

        const threatsDetected = highRiskCount + maliciousCount;
        const averageRisk = Math.round(sumRisk / totalScans);

        const topAttackVectors = Object.entries(vectorFrequencies)
            .map(([name, count]) => ({
                name,
                count,
                percentage: Math.round((count / totalScans) * 100)
            }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 5);

        return {
            hasData: true,
            totalScans,
            threatsDetected,
            suspiciousCount,
            safeCount,
            highRiskCount,
            maliciousCount,
            averageRisk,
            verdictDistribution: {
                safe: Math.round((safeCount / totalScans) * 100),
                suspicious: Math.round((suspiciousCount / totalScans) * 100),
                highRisk: Math.round((highRiskCount / totalScans) * 100),
                malicious: Math.round((maliciousCount / totalScans) * 100)
            },
            artifactDistribution: artifactCounts,
            topAttackVectors
        };
    }
}

