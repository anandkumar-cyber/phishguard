/**
 * Master Deterministic Heuristic Engine
 * Dispatches artifact inputs to specialized domain analyzers and returns uniform analysis objects.
 */

import { analyzeUrl } from './url/urlAnalyzer.js';
import { analyzeMessage } from './message/messageAnalyzer.js';
import { analyzeApk } from './apk/apkAnalyzer.js';
import { buildThreatReport } from './scoring/riskScorer.js';

export class HeuristicEngine {
    constructor() {
        this.version = '3.0.0-PROD';
    }

    /**
     * Executes offline deterministic analysis based on artifact type
     */
    analyze(input, type = 'url') {
        const cleanType = (type || 'url').toLowerCase();
        let deterministicResult;

        switch (cleanType) {
            case 'url':
                deterministicResult = analyzeUrl(input);
                break;
            case 'message':
            case 'sms':
                deterministicResult = analyzeMessage(input, false);
                break;
            case 'email':
                deterministicResult = analyzeMessage(input, true);
                break;
            case 'apk':
                deterministicResult = analyzeApk(input);
                break;
            default:
                deterministicResult = analyzeUrl(input);
                break;
        }

        return deterministicResult;
    }

    /**
     * Synthesizes deterministic results with optional AI results to produce the final Threat Report
     */
    generateReport(deterministicResult, aiResult = null, type = 'url') {
        return buildThreatReport({
            deterministicResult,
            aiResult,
            artifactType: type
        });
    }
}

export const heuristicEngine = new HeuristicEngine();

