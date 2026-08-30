/**
 * Local Storage & Persistence Service
 * Manages scan investigation history, search filtering, and user BYOK preferences safely.
 */

const HISTORY_KEY = 'phishguard_investigations_v2';
const SETTINGS_KEY = 'phishguard_user_settings_v2';
const MAX_HISTORY_ITEMS = 50;

export class StorageService {
    constructor() {
        this.migrateLegacyStorage();
    }

    migrateLegacyStorage() {
        try {
            if (typeof localStorage === 'undefined') return;
            const old = localStorage.getItem('phishguard_history');
            if (old && !localStorage.getItem(HISTORY_KEY)) {
                const parsed = JSON.parse(old);
                if (Array.isArray(parsed)) {
                    const migrated = parsed.map(item => ({
                        id: item.id ? `PG-LEGACY-${item.id}` : `PG-${Date.now()}`,
                        timestamp: item.ts || new Date().toISOString(),
                        artifactType: item.type || 'url',
                        input: item.input || '',
                        riskScore: item.score || 0,
                        verdict: item.verdict || 'SUSPICIOUS',
                        verdictColor: (item.verdict || '').toLowerCase() === 'safe' ? 'emerald' : 'amber',
                        summary: item.summary || 'Legacy scan entry',
                        recommendation: 'Historical record.',
                        indicators: item.flags || [],
                        whyReasons: [],
                        threatMatrix: []
                    }));
                    localStorage.setItem(HISTORY_KEY, JSON.stringify(migrated));
                }
            }
        } catch (e) {
            console.warn('[PhishGuard Storage] Migration warning:', e);
        }
    }

    getHistory() {
        try {
            if (typeof localStorage === 'undefined') return [];
            const raw = localStorage.getItem(HISTORY_KEY);
            if (!raw) return [];
            const parsed = JSON.parse(raw);
            return Array.isArray(parsed) ? parsed : [];
        } catch (e) {
            console.error('[PhishGuard Storage] Failed to load history:', e);
            return [];
        }
    }

    addScan(report) {
        if (!report || !report.id) return;
        try {
            if (typeof localStorage === 'undefined') return;
            const history = this.getHistory();
            const filtered = history.filter(h => h.id !== report.id);
            filtered.unshift(report);
            if (filtered.length > MAX_HISTORY_ITEMS) {
                filtered.length = MAX_HISTORY_ITEMS;
            }
            localStorage.setItem(HISTORY_KEY, JSON.stringify(filtered));
        } catch (e) {
            console.error('[PhishGuard Storage] Failed to add scan:', e);
        }
    }

    deleteScan(id) {
        try {
            if (typeof localStorage === 'undefined') return false;
            const history = this.getHistory();
            const updated = history.filter(h => h.id !== id);
            localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
            return true;
        } catch (e) {
            console.error('[PhishGuard Storage] Failed to delete scan:', e);
            return false;
        }
    }

    clearHistory() {
        try {
            if (typeof localStorage === 'undefined') return false;
            localStorage.removeItem(HISTORY_KEY);
            return true;
        } catch (e) {
            console.error('[PhishGuard Storage] Failed to clear history:', e);
            return false;
        }
    }

    getSettings() {
        const defaults = {
            apiKey: '',
            engineMode: 'hybrid', // 'hybrid' | 'deterministic' | 'ai_only'
            theme: 'dark',
            autoClearHours: 0
        };

        try {
            if (typeof localStorage === 'undefined') return defaults;
            const raw = localStorage.getItem(SETTINGS_KEY);
            if (!raw) return defaults;
            return { ...defaults, ...JSON.parse(raw) };
        } catch (e) {
            return defaults;
        }
    }

    saveSettings(settings) {
        try {
            if (typeof localStorage === 'undefined') return false;
            const current = this.getSettings();
            const updated = { ...current, ...settings };
            localStorage.setItem(SETTINGS_KEY, JSON.stringify(updated));
            return true;
        } catch (e) {
            console.error('[PhishGuard Storage] Failed to save settings:', e);
            return false;
        }
    }

    wipeAllData() {
        try {
            if (typeof localStorage === 'undefined') return false;
            localStorage.removeItem(HISTORY_KEY);
            localStorage.removeItem(SETTINGS_KEY);
            return true;
        } catch (e) {
            return false;
        }
    }
}

export const storageService = new StorageService();

