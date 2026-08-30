/**
 * Top-Level Domain (TLD) Threat Intelligence Metadata
 * Classifies TLD risk based on statistical registration abuse rates.
 * Note: An elevated risk signal does not determine malice on its own; it serves as a contextual weight factor.
 */

export const TLD_RISK_REGISTRY = {
    'xyz': { score: 14, category: 'elevated', rationale: 'Statistically high volume of automated low-cost registrations in spam and phishing campaigns.' },
    'top': { score: 14, category: 'elevated', rationale: 'Frequently identified in automated disposable domain threat feeds.' },
    'tk': { score: 18, category: 'elevated', rationale: 'Historically abused free domain registry with high malicious concentration.' },
    'ml': { score: 18, category: 'elevated', rationale: 'Historically abused free domain registry.' },
    'ga': { score: 18, category: 'elevated', rationale: 'Historically abused free domain registry.' },
    'cf': { score: 18, category: 'elevated', rationale: 'Historically abused free domain registry.' },
    'gq': { score: 18, category: 'elevated', rationale: 'Historically abused free domain registry.' },
    'buzz': { score: 12, category: 'elevated', rationale: 'Elevated prevalence in spam redirection chains.' },
    'work': { score: 12, category: 'elevated', rationale: 'Observed in low-cost social engineering lure campaigns.' },
    'click': { score: 14, category: 'elevated', rationale: 'Commonly utilized in click-fraud and phishing redirectors.' },
    'rest': { score: 10, category: 'elevated', rationale: 'Elevated risk signal based on threat feed prevalence.' },
    'fit': { score: 10, category: 'elevated', rationale: 'Elevated risk signal based on threat feed prevalence.' },
    'surf': { score: 12, category: 'elevated', rationale: 'Observed in temporary campaign registrations.' },
    'monster': { score: 12, category: 'elevated', rationale: 'Elevated risk signal.' },
    'cam': { score: 10, category: 'elevated', rationale: 'Common in social engineering lures.' },
    'ru': { score: 10, category: 'elevated', rationale: 'Geographical TLD with elevated frequency in bulletproof hosting infrastructure.' },
    'su': { score: 14, category: 'elevated', rationale: 'Legacy Soviet TLD frequently hosting bulletproof infrastructure.' }
};

export const HIGH_TRUST_TLDS = {
    'gov': { trustBonus: -20, rationale: 'Strictly restricted to verified US governmental entities.' },
    'mil': { trustBonus: -20, rationale: 'Strictly restricted to US military infrastructure.' },
    'edu': { trustBonus: -10, rationale: 'Restricted to accredited postsecondary educational institutions.' },
    'gov.in': { trustBonus: -20, rationale: 'Official Government of India national domain.' },
    'gov.uk': { trustBonus: -20, rationale: 'Official UK Government public sector domain.' }
};

