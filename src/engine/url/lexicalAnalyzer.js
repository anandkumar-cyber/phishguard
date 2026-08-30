/**
 * Lexical & Structural URL Vector Analyzer
 * Examines IP-as-host, embedded credentials, excessive subdomains, security lure keywords, open redirects, and encoding obfuscations.
 */

const SUSPICIOUS_AUTH_KEYWORDS = [
    'signin', 'sign-in', 'verify', 'verification', 'banking',
    'wallet', 'token', 'session', 'auth', 'authorize',
    'password', 'credential', 'recovery', 'kyc', 'reauth'
];

const SUSPICIOUS_REDIRECT_PARAMS = [
    'redirect', 'redirect_to', 'redirect_url', 'return', 'return_url',
    'url', 'next', 'dest', 'destination', 'target', 'link', 'goto', 'r', 'u'
];

const URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy', 'goo.gl',
    'ow.ly', 'buff.ly', 'shorturl.at', 'tiny.cc', 'bc.vc', 'adf.ly'
];

const DANGEROUS_FILE_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.wsf', '.iso', '.img', '.apk', '.jar', '.ps1', '.msi'
];

export function analyzeLexicalVectors(parsedUrl, rawInput) {
    const indicators = [];
    let riskPoints = 0;

    const hostname = parsedUrl.hostname ? parsedUrl.hostname.toLowerCase() : '';
    const pathname = parsedUrl.pathname ? parsedUrl.pathname.toLowerCase() : '';
    const search = parsedUrl.search ? parsedUrl.search.toLowerCase() : '';
    const raw = rawInput || '';

    // 1. IP Address as Hostname
    const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const isIpv6 = hostname.startsWith('[') || /^[0-9a-f:]+$/i.test(hostname) && hostname.includes(':');
    
    if (isIpv4 || isIpv6) {
        indicators.push({
            id: 'HOST_IP_ADDRESS',
            category: 'Domain & Host',
            severity: 'danger',
            title: 'Direct IP Address Used as Hostname',
            description: `The URL connects directly to raw IP address "${hostname}" instead of a registered domain name. Direct IPs are frequently used to evade domain-based reputation filters.`
        });
        riskPoints += 30;
    }

    // 2. Embedded Basic Auth Credentials or @ symbol masquerade in URL Authority
    let hasAuthMasquerade = Boolean(parsedUrl.username || parsedUrl.password);
    if (!hasAuthMasquerade) {
        const schemeEnd = raw.indexOf('://');
        const searchStart = schemeEnd !== -1 ? schemeEnd + 3 : 0;
        const firstSlash = raw.indexOf('/', searchStart);
        const authorityPart = firstSlash !== -1 ? raw.slice(0, firstSlash) : raw;
        if (authorityPart.includes('@')) {
            hasAuthMasquerade = true;
        }
    }

    if (hasAuthMasquerade) {
        indicators.push({
            id: 'AUTH_CREDENTIAL_INJECTION',
            category: 'Obfuscation',
            severity: 'danger',
            title: 'Deceptive Credential / @ Masquerade in URL',
            description: 'The URL authority uses the "@" character. Browsers treat text before "@" as basic authentication credentials and actually navigate to the domain after the "@", tricking users who only read the prefix of the URL.'
        });
        riskPoints += 35;
    }

    // 3. Excessive Subdomain Nesting (> 3 subdomains)
    const hostParts = hostname.split('.').filter(Boolean);
    if (hostParts.length >= 4 && !isIpv4) {
        indicators.push({
            id: 'DEEP_SUBDOMAIN_NESTING',
            category: 'Domain & Host',
            severity: 'warning',
            title: 'Excessive Subdomain Nesting Depth',
            description: `The host contains ${hostParts.length - 2} subdomain levels ("${hostname}"). Cybercriminals frequently chain long subdomains to hide the true root domain on mobile address bars.`
        });
        riskPoints += 15;
    }

    // 4. URL Shortener Detection
    if (URL_SHORTENERS.includes(hostname)) {
        indicators.push({
            id: 'URL_SHORTENER_DETECTED',
            category: 'Transport & Routing',
            severity: 'warning',
            title: 'URL Shortener Service Used',
            description: `The link uses shortening service "${hostname}". Shortened URLs mask the true destination endpoint and should be expanded before visiting.`
        });
        riskPoints += 25;
    }

    // 5. Credential & Authentication Lure Keywords in Path / Query
    const fullPathAndQuery = `${pathname}${search}`;
    const matchedKeywords = SUSPICIOUS_AUTH_KEYWORDS.filter(kw => {
        const regex = new RegExp(`[\\/\\-_?&=]${kw}([\\/\\-_?&=]|$)`, 'i');
        return regex.test(fullPathAndQuery);
    });

    if (matchedKeywords.length > 0) {
        const severity = matchedKeywords.length >= 2 ? 'danger' : 'warning';
        indicators.push({
            id: 'SUSPICIOUS_LURE_KEYWORDS',
            category: 'Lexical Analysis',
            severity,
            title: 'Authentication & Credential Lure Keywords Detected',
            description: `URL path/query contains sensitive keywords: [${matchedKeywords.slice(0, 4).join(', ')}]. Frequently associated with fake login portals or credential interceptors.`
        });
        riskPoints += Math.min(25, matchedKeywords.length * 10);
    }

    // 6. Suspicious Redirect Parameters (Open Redirect Vector)
    const params = new URLSearchParams(search);
    const redirectParamsFound = [];
    for (const [key, value] of params.entries()) {
        if (SUSPICIOUS_REDIRECT_PARAMS.includes(key.toLowerCase()) && (value.startsWith('http://') || value.startsWith('https://') || value.startsWith('//'))) {
            redirectParamsFound.push({ param: key, target: value });
        }
    }

    if (redirectParamsFound.length > 0) {
        indicators.push({
            id: 'POTENTIAL_OPEN_REDIRECT',
            category: 'Transport & Routing',
            severity: 'warning',
            title: 'Embedded Destination Redirect Parameter Found',
            description: `URL contains redirection parameter "${redirectParamsFound[0].param}" pointing to external target "${redirectParamsFound[0].target}". Attackers exploit open redirects to bounce users through legitimate websites to phishing traps.`
        });
        riskPoints += 25;
    }

    // 7. Obfuscated Hex / Double Percent Encoding
    const percentCount = (raw.match(/%/g) || []).length;
    if (percentCount >= 4) {
        indicators.push({
            id: 'HEAVY_PERCENT_ENCODING',
            category: 'Obfuscation',
            severity: 'warning',
            title: 'Heavy Percent-Encoding / Character Obfuscation',
            description: `URL contains ${percentCount} percent-encoded tokens ("%xx"), indicating potential obfuscation to conceal payloads from gateway filters.`
        });
        riskPoints += 15;
    }

    // 8. Dangerous Executable / Binary File Extension in Path
    for (const ext of DANGEROUS_FILE_EXTENSIONS) {
        if (pathname.endsWith(ext)) {
            indicators.push({
                id: 'DANGEROUS_DOWNLOAD_EXTENSION',
                category: 'Payload Analysis',
                severity: 'danger',
                title: `Direct Executable / Script Payload Extension (${ext})`,
                description: `URL path directly points to an executable or binary file type ("${ext}"). Visiting may trigger an unprompted drive-by download.`
            });
            riskPoints += 35;
            break;
        }
    }

    // 9. Insecure Protocol
    if (parsedUrl.protocol === 'http:') {
        indicators.push({
            id: 'UNENCRYPTED_HTTP_PROTOCOL',
            category: 'Transport & Routing',
            severity: 'info',
            title: 'Unencrypted HTTP Protocol',
            description: 'The URL uses unencrypted plaintext HTTP rather than HTTPS. Modern legitimate authentication endpoints require encrypted transport.'
        });
        riskPoints += 8;
    }

    // 10. Non-standard Port
    if (parsedUrl.port && !['80', '443', ''].includes(parsedUrl.port)) {
        indicators.push({
            id: 'NON_STANDARD_PORT',
            category: 'Domain & Host',
            severity: 'warning',
            title: `Non-Standard Network Port Specified (:${parsedUrl.port})`,
            description: `The URL specifies non-standard service port :${parsedUrl.port}. Phishing sites often host web servers on irregular ports to bypass default gateway monitoring.`
        });
        riskPoints += 12;
    }

    return {
        indicators,
        riskPoints
    };
}

