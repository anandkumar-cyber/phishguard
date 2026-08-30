/**
 * AI Threat Intelligence Service (Google Gemini 2.5 Flash Integration)
 * BYOK (Bring Your Own Key) Architecture.
 * Provides optional contextual AI threat analysis as an augmentation layer with graceful fallback and strict validation.
 */

export class AiThreatService {
    constructor() {
        this.modelName = 'gemini-2.5-flash';
    }

    /**
     * Validates and sanitizes raw JSON output returned from Gemini API
     */
    validateAndSanitizeOutput(parsed) {
        if (!parsed || typeof parsed !== 'object') return null;

        // Clamp risk score to an integer between 0 and 100
        let riskScore = Number(parsed.risk_score);
        if (isNaN(riskScore)) riskScore = 50;
        riskScore = Math.max(0, Math.min(100, Math.round(riskScore)));

        // Validate verdict enum
        const validVerdicts = ['SAFE', 'SUSPICIOUS', 'HIGH_RISK', 'MALICIOUS'];
        let verdict = typeof parsed.verdict === 'string' ? parsed.verdict.toUpperCase().trim() : 'SUSPICIOUS';
        if (!validVerdicts.includes(verdict)) {
            verdict = riskScore <= 24 ? 'SAFE' : riskScore <= 59 ? 'SUSPICIOUS' : riskScore <= 84 ? 'HIGH_RISK' : 'MALICIOUS';
        }

        // Sanitize summary string
        const summary = typeof parsed.summary === 'string' ? parsed.summary.trim() : 'AI contextual threat assessment.';

        // Sanitize recommendation string
        const recommendation = typeof parsed.recommendation === 'string' ? parsed.recommendation.trim() : 'Exercise caution and verify the source.';

        // Validate flags array
        const flags = [];
        if (Array.isArray(parsed.flags)) {
            for (const f of parsed.flags) {
                if (f && typeof f === 'object' && typeof f.text === 'string' && f.text.trim() !== '') {
                    const level = ['danger', 'warning', 'info'].includes(f.level) ? f.level : 'warning';
                    flags.push({ level, text: f.text.trim() });
                }
            }
        }

        return {
            verdict,
            risk_score: riskScore,
            summary,
            recommendation,
            flags
        };
    }

    /**
     * Executes AI-augmented threat analysis
     * @param {string} input Raw artifact string
     * @param {string} type Artifact type ('url', 'message', 'email', 'apk')
     * @param {object} deterministicAnalysis Results from local HeuristicEngine
     * @param {string} apiKey User-provided Gemini API Key
     */
    async analyze(input, type, deterministicAnalysis, apiKey) {
        if (!apiKey || typeof apiKey !== 'string' || apiKey.trim() === '') {
            return {
                success: false,
                reason: 'NO_API_KEY',
                message: 'No API key provided. Using offline deterministic heuristic analysis.'
            };
        }

        const cleanKey = apiKey.trim();
        const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${this.modelName}:generateContent?key=${cleanKey}`;
        const prompt = this.constructPrompt(input, type, deterministicAnalysis);

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 12000); // 12-second timeout

            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                signal: controller.signal,
                body: JSON.stringify({
                    contents: [{ parts: [{ text: prompt }] }],
                    generationConfig: {
                        temperature: 0.1,
                        responseMimeType: 'application/json',
                        responseSchema: {
                            type: 'OBJECT',
                            properties: {
                                verdict: { type: 'STRING', enum: ['SAFE', 'SUSPICIOUS', 'HIGH_RISK', 'MALICIOUS'] },
                                risk_score: { type: 'INTEGER' },
                                summary: { type: 'STRING' },
                                threat_category: { type: 'STRING' },
                                flags: {
                                    type: 'ARRAY',
                                    items: {
                                        type: 'OBJECT',
                                        properties: {
                                            level: { type: 'STRING', enum: ['danger', 'warning', 'info'] },
                                            text: { type: 'STRING' }
                                        },
                                        required: ['level', 'text']
                                    }
                                },
                                recommendation: { type: 'STRING' }
                            },
                            required: ['verdict', 'risk_score', 'summary', 'flags', 'recommendation']
                        }
                    }
                })
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                const errMsg = errData?.error?.message || `HTTP ${response.status}`;
                return {
                    success: false,
                    reason: 'API_ERROR',
                    message: `Gemini API returned error (${errMsg}). Falling back to local heuristics.`
                };
            }

            const data = await response.json();
            const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text;

            if (!rawText) {
                return {
                    success: false,
                    reason: 'EMPTY_RESPONSE',
                    message: 'Gemini returned an empty candidate payload. Falling back to local heuristics.'
                };
            }

            let parsed;
            try {
                parsed = JSON.parse(rawText);
            } catch (e) {
                return {
                    success: false,
                    reason: 'PARSE_ERROR',
                    message: 'Invalid JSON response from AI provider. Falling back to local heuristics.'
                };
            }

            const sanitized = this.validateAndSanitizeOutput(parsed);
            if (!sanitized) {
                return {
                    success: false,
                    reason: 'SCHEMA_INVALID',
                    message: 'AI response failed structural schema validation. Falling back to local heuristics.'
                };
            }

            return {
                success: true,
                data: sanitized
            };

        } catch (err) {
            const isAbort = err.name === 'AbortError';
            return {
                success: false,
                reason: isAbort ? 'TIMEOUT' : 'NETWORK_ERROR',
                message: isAbort 
                    ? 'AI analysis timed out after 12s. Showing local heuristic analysis.'
                    : `Network error connecting to AI service: ${err.message}. Showing local heuristic analysis.`
            };
        }
    }

    constructPrompt(input, type, deterministic) {
        const detectedIndicators = (deterministic.indicators || []).map(i => `• [${i.severity.toUpperCase()}] ${i.title}`).join('\n');

        return `You are an enterprise cybersecurity threat analyst performing multi-factor digital artifact triage.
Analyze the following ${type.toUpperCase()} artifact for phishing, credential harvesting, social engineering, and cyber threats.

[ARTIFACT TYPE]: ${type.toUpperCase()}
[ARTIFACT DATA]:
${input}

[LOCAL HEURISTIC FINDINGS]:
${detectedIndicators || 'No preliminary heuristic flags detected.'}

INSTRUCTIONS:
1. Provide a rigorous, objective threat assessment.
2. "verdict" must be one of: "SAFE", "SUSPICIOUS", "HIGH_RISK", "MALICIOUS".
3. "risk_score" must be an integer from 0 to 100.
4. "flags" should list specific technical and behavioral observations.
5. "recommendation" must give concrete, actionable mitigation guidance for a SOC analyst or end user.`;
    }
}

export const aiThreatService = new AiThreatService();

