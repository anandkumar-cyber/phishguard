/**
 * Universal HTML Sanitization and XSS Prevention Utilities
 */

export function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

export function sanitizeUrl(url) {
    if (typeof url !== 'string') return '';
    const trimmed = url.trim();
    if (/^(javascript|data|vbscript):/i.test(trimmed)) {
        return '#unsafe-protocol-blocked';
    }
    return trimmed;
}

export function safeTruncate(str, maxLength = 60) {
    if (typeof str !== 'string') return '';
    return str.length > maxLength ? str.slice(0, maxLength) + '…' : str;
}

