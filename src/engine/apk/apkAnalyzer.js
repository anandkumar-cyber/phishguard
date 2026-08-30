/**
 * Master Android Package (APK) Identifier Security Analyzer
 */

import { analyzeApkPackageStructure } from './packageAnalyzer.js';

export function analyzeApk(rawInput) {
    if (!rawInput || typeof rawInput !== 'string' || rawInput.trim() === '') {
        return {
            isValid: false,
            error: 'Empty or missing APK package name',
            indicators: [],
            riskScore: 0
        };
    }

    const pkgName = rawInput.trim();
    const result = analyzeApkPackageStructure(pkgName);

    const calculatedScore = Math.max(0, Math.min(100, Math.round(result.riskPoints)));

    return {
        isValid: true,
        artifactType: 'apk',
        input: pkgName,
        packageParts: result.packageParts,
        analysisScope: 'PACKAGE_NAMESPACE_STRUCTURAL_HEURISTICS',
        scopeDisclaimer: 'Heuristic analysis is performed on package name architecture, reverse-DNS namespace legitimacy, and trojanized suffix patterns. (Full APK binary bytecode decompilation / DEX static analysis is not performed in-browser).',
        indicators: result.indicators,
        rawRiskPoints: result.riskPoints,
        calculatedScore
    };
}

