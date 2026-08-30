/**
 * Centralized High-Value Brand Target Dataset
 * Used for Levenshtein edit-distance calculations, combosquatting detection, and subdomain shadowing heuristics.
 */

export const TARGET_BRANDS = [
    {
        name: 'PayPal',
        slug: 'paypal',
        canonicalDomains: ['paypal.com', 'paypal.me'],
        aliases: ['paypa1', 'paypai', 'paypal-security', 'paypal-verify']
    },
    {
        name: 'Google',
        slug: 'google',
        canonicalDomains: ['google.com', 'google.co.in', 'google.co.uk', 'gmail.com', 'accounts.google.com'],
        aliases: ['goog1e', 'g00gle', 'google-security']
    },
    {
        name: 'Microsoft',
        slug: 'microsoft',
        canonicalDomains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'office365.com'],
        aliases: ['rnicrosoft', 'micros0ft', 'ms-security']
    },
    {
        name: 'Apple',
        slug: 'apple',
        canonicalDomains: ['apple.com', 'icloud.com'],
        aliases: ['app1e', 'apple-support', 'icloud-login']
    },
    {
        name: 'Amazon',
        slug: 'amazon',
        canonicalDomains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'aws.amazon.com'],
        aliases: ['amaz0n', 'amazn', 'amazon-order']
    },
    {
        name: 'Netflix',
        slug: 'netflix',
        canonicalDomains: ['netflix.com'],
        aliases: ['netf1ix', 'netflix-billing']
    },
    {
        name: 'Chase Bank',
        slug: 'chase',
        canonicalDomains: ['chase.com'],
        aliases: ['chase-verify', 'chase-security']
    },
    {
        name: 'State Bank of India',
        slug: 'sbi',
        canonicalDomains: ['onlinesbi.sbi', 'sbi.co.in'],
        aliases: ['sbi-kyc', 'sbi-update', 'sbi-card']
    },
    {
        name: 'HDFC Bank',
        slug: 'hdfc',
        canonicalDomains: ['hdfcbank.com'],
        aliases: ['hdfc-alert', 'hdfc-kyc']
    },
    {
        name: 'ICICI Bank',
        slug: 'icici',
        canonicalDomains: ['icicibank.com'],
        aliases: ['icici-verify']
    },
    {
        name: 'Bank of America',
        slug: 'bankofamerica',
        canonicalDomains: ['bankofamerica.com'],
        aliases: ['bofa-login']
    },
    {
        name: 'Wells Fargo',
        slug: 'wellsfargo',
        canonicalDomains: ['wellsfargo.com'],
        aliases: ['wellsfargo-auth']
    },
    {
        name: 'Binance',
        slug: 'binance',
        canonicalDomains: ['binance.com'],
        aliases: ['binance-auth']
    },
    {
        name: 'Coinbase',
        slug: 'coinbase',
        canonicalDomains: ['coinbase.com'],
        aliases: ['coinbase-login']
    },
    {
        name: 'MetaMask',
        slug: 'metamask',
        canonicalDomains: ['metamask.io'],
        aliases: ['metamask-wallet']
    },
    {
        name: 'WhatsApp',
        slug: 'whatsapp',
        canonicalDomains: ['whatsapp.com', 'web.whatsapp.com'],
        aliases: ['whatsapp-update']
    },
    {
        name: 'Instagram',
        slug: 'instagram',
        canonicalDomains: ['instagram.com'],
        aliases: ['instagram-verify']
    },
    {
        name: 'Facebook / Meta',
        slug: 'facebook',
        canonicalDomains: ['facebook.com', 'meta.com'],
        aliases: ['fb-security']
    },
    {
        name: 'GitHub',
        slug: 'github',
        canonicalDomains: ['github.com', 'github.io', 'githubusercontent.com'],
        aliases: ['g1thub']
    },
    {
        name: 'GitLab',
        slug: 'gitlab',
        canonicalDomains: ['gitlab.com'],
        aliases: ['g1tlab']
    },
    {
        name: 'DocuSign',
        slug: 'docusign',
        canonicalDomains: ['docusign.com', 'docusign.net'],
        aliases: ['docusign-review']
    },
    {
        name: 'Dropbox',
        slug: 'dropbox',
        canonicalDomains: ['dropbox.com'],
        aliases: ['dropbox-share']
    },
    {
        name: 'Adobe',
        slug: 'adobe',
        canonicalDomains: ['adobe.com'],
        aliases: ['adobe-document']
    },
    {
        name: 'Steam',
        slug: 'steam',
        canonicalDomains: ['store.steampowered.com', 'steamcommunity.com'],
        aliases: ['steam-trade', 'steampowered-gift']
    },
    {
        name: 'Discord',
        slug: 'discord',
        canonicalDomains: ['discord.com', 'discord.gg'],
        aliases: ['discord-nitro']
    },
    {
        name: 'Spotify',
        slug: 'spotify',
        canonicalDomains: ['spotify.com'],
        aliases: ['spotify-premium']
    },
    {
        name: 'FedEx',
        slug: 'fedex',
        canonicalDomains: ['fedex.com'],
        aliases: ['fedex-tracking', 'fedex-delivery']
    },
    {
        name: 'DHL',
        slug: 'dhl',
        canonicalDomains: ['dhl.com'],
        aliases: ['dhl-parcel']
    },
    {
        name: 'USPS',
        slug: 'usps',
        canonicalDomains: ['usps.com'],
        aliases: ['usps-track']
    }
];

export const BRAND_SLUGS = TARGET_BRANDS.map(b => b.slug);

