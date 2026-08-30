/**
 * Urgency & Psychological Coercion Linguistic Analyzer
 * Detects artificial time constraints, panic triggers, legal threats, and account suspension pressure in SMS and email communications.
 */

const URGENCY_PATTERNS = [
    { regex: /\b(immediately|urgent|urgently|right now|act now|hurry|instantly|asap)\b/i, weight: 15, tag: 'High Urgency' },
    { regex: /\b(within (24|12|48|1|2|3) hours?|in (24|12|48) hrs?|today only|expires soon|time limit)\b/i, weight: 20, tag: 'Artificial Deadline' },
    { regex: /\b(suspended|locked|blocked|deactivated|frozen|terminated|restricted|disabled)\b/i, weight: 25, tag: 'Account Status Threat' },
    { regex: /\b(legal action|law enforcement|police|court|fine|penalty|arrest|summons|irs notice)\b/i, weight: 30, tag: 'Fear / Coercion Lure' },
    { regex: /\b(unauthorized (access|activity|transaction|login)|suspicious activity detected)\b/i, weight: 20, tag: 'Security Alarm Trigger' },
    { regex: /\b(avoid (loss|fees|closure|suspension|deactivation))\b/i, weight: 15, tag: 'Loss Aversion' }
];

export function analyzeUrgencyPatterns(text) {
    if (!text || typeof text !== 'string') return { indicators: [], score: 0, matchedTags: [] };

    const indicators = [];
    const matchedTags = [];
    let totalScore = 0;

    for (const pattern of URGENCY_PATTERNS) {
        if (pattern.regex.test(text)) {
            matchedTags.push(pattern.tag);
            totalScore += pattern.weight;
        }
    }

    if (matchedTags.length > 0) {
        const severity = matchedTags.length >= 2 || totalScore >= 40 ? 'danger' : 'warning';
        indicators.push({
            id: 'PSYCHOLOGICAL_URGENCY_TRIGGER',
            category: 'Social Engineering',
            severity,
            title: 'Urgency & Fear-Based Coercion Detected',
            description: `Message relies on psychological pressure tactics: [${matchedTags.join(', ')}]. Social engineers use manufactured urgency to bypass rational scrutiny.`
        });
    }

    return {
        indicators,
        score: Math.min(50, totalScore),
        matchedTags
    };
}

