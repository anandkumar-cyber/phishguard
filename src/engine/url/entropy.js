/**
 * Shannon Entropy Calculator for Strings & Domains
 * Higher entropy in domain names often correlates with algorithmic domain generation (DGA) or random hex strings.
 */

export function calculateShannonEntropy(str) {
    if (!str || typeof str !== 'string' || str.length === 0) return 0;
    
    const len = str.length;
    const frequencies = {};
    
    for (let i = 0; i < len; i++) {
        const char = str[i];
        frequencies[char] = (frequencies[char] || 0) + 1;
    }
    
    let entropy = 0;
    for (const char in frequencies) {
        const p = frequencies[char] / len;
        entropy -= p * Math.log2(p);
    }
    
    return Number(entropy.toFixed(3));
}

export function evaluateDomainEntropy(domain) {
    if (!domain) return { entropy: 0, isHighEntropy: false, level: 'normal', explanation: 'No domain provided' };
    
    // Extract base domain name without TLD
    const parts = domain.toLowerCase().split('.');
    const mainName = parts.length > 1 ? parts.slice(0, -1).join('') : domain;
    
    const entropy = calculateShannonEntropy(mainName);
    
    let isHighEntropy = false;
    let level = 'normal';
    let explanation = 'Standard lexical variability';
    
    if (mainName.length >= 8 && entropy >= 3.85) {
        isHighEntropy = true;
        level = 'elevated';
        explanation = `High Shannon entropy (${entropy} bits/char) detected; suggests randomly generated or obfuscated hostname.`;
    } else if (mainName.length >= 6 && entropy >= 3.5) {
        level = 'moderate';
        explanation = `Moderate lexical entropy (${entropy} bits/char).`;
    }
    
    return {
        entropy,
        isHighEntropy,
        level,
        explanation
    };
}

