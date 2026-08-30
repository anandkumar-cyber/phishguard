/**
 * ==============================================================================
 * PHISHGUARD APPLICATION ORCHESTRATOR & SOC WORKBENCH
 * Architecture: Modular ES6 Modules, Dual-Core Engine, BYOK AI Synthesis
 * ==============================================================================
 */

import { heuristicEngine } from './src/engine/HeuristicEngine.js';
import { aiThreatService } from './src/services/AiThreatService.js';
import { storageService } from './src/services/StorageService.js';
import { ReportExporter } from './src/services/ReportExporter.js';
import { AnalyticsEngine } from './src/analytics/AnalyticsEngine.js';
import { escapeHtml, sanitizeUrl, safeTruncate } from './src/utils/sanitization.js';
import { copyToClipboard } from './src/utils/clipboard.js';
import { analyzeUrl } from './src/engine/url/urlAnalyzer.js';

class PhishGuardApp {
    constructor() {
        this.currentView = 'overview';
        this.currentVector = 'url';
        this.isScanning = false;
        this.currentReport = null;

        this.vectorConfigs = {
            url: {
                label: 'Paste a suspicious URL or link to inspect',
                placeholder: 'https://paypa1-security-login.ru/verify?token=abc123',
                samples: [
                    'http://paypa1-security-login.ru/verify?token=abc123',
                    'https://xn--pple-43d.com/login',
                    'http://192.168.1.100:8080/admin/auth',
                    'https://google.com/search?q=cybersecurity',
                    'https://github.com/fastapi/fastapi'
                ]
            },
            message: {
                label: 'Paste a suspicious SMS or chat message to analyze',
                placeholder: "URGENT: Your SBI account has been locked. Verify immediately at http://sbi-secure.ru/verify within 24 hours.",
                samples: [
                    'URGENT: Your SBI account has been locked due to missing KYC. Update immediately at http://sbi-secure.ru/verify within 24 hours.',
                    'Congratulations! You have won a cash reward of $5,000. Send your OTP to claim now.',
                    'Hi Team, are we still meeting for the Q3 project review at 3 PM today in Room 4B?'
                ]
            },
            email: {
                label: 'Paste email headers, sender address, and body content',
                placeholder: 'From: "PayPal Security" <billing-alert98@gmail.com>\nSubject: Action Required: Your account is suspended\n\nPlease verify credentials.',
                samples: [
                    'From: "PayPal Security" <billing-alert98@gmail.com>\nSubject: Action Required: Your account is suspended\n\nPlease verify your credentials at http://paypal-reauth.xyz',
                    'From: support@github.com\nSubject: [GitHub] A personal access token has expired\n\nYour token has expired.',
                    'From: "CEO Office" <urgent-wire@temporary-mail.top>\nSubject: URGENT: Wire Transfer Authorization\n\nInitiate $45,000 wire to vendor immediately.'
                ]
            },
            apk: {
                label: 'Enter an Android package name (reverse-DNS format) to check',
                placeholder: 'com.whatsapp.update.pro.free.unlimited',
                samples: [
                    'com.whatsapp.update.pro.free.unlimited',
                    'com.android.system.security.patch.installer',
                    'com.google.android.youtube',
                    'com.free.gems.generator.clash.royale'
                ]
            }
        };
    }

    init() {
        this.cacheDom();
        this.bindEvents();
        this.applySettingsTheme();
        this.renderVectorSamples('url');
        this.renderOverview();
        this.initUrlInspector();
        this.updateSidebarEngineStatus();
        console.log('🛡️ [PhishGuard] Application initialized successfully.');
    }

    cacheDom() {
        this.dom = {
            sidebar: document.getElementById('sidebar'),
            mobileToggleBtn: document.getElementById('mobile-menu-toggle'),
            navItems: document.querySelectorAll('.sidebar-nav .nav-item, [data-view]'),
            viewSections: document.querySelectorAll('.view-section'),
            pageTitle: document.getElementById('page-title'),
            themeToggleBtn: document.getElementById('theme-toggle-btn'),
            themeLabel: document.getElementById('theme-btn-label'),
            sidebarEngineModeText: document.getElementById('sidebar-engine-mode-text'),
            
            // Scanner
            vectorTabBar: document.getElementById('vector-tab-bar'),
            vectorTabBtns: document.querySelectorAll('.vector-tab-btn'),
            inputLabel: document.getElementById('input-instructions-label'),
            artifactInput: document.getElementById('artifact-input'),
            charCounter: document.getElementById('char-counter'),
            btnClearInput: document.getElementById('btn-clear-input'),
            sampleChipsContainer: document.getElementById('sample-chips-container'),
            btnExecuteScan: document.getElementById('btn-execute-scan'),
            btnScanText: document.getElementById('btn-scan-text'),
            scanPipeline: document.getElementById('scan-pipeline'),
            pipelineStepsList: document.getElementById('pipeline-steps-list'),
            resultHudContainer: document.getElementById('result-hud-container'),
            
            // Overview KPIs & Table
            kpiTotalScans: document.getElementById('kpi-total-scans'),
            kpiThreatsDetected: document.getElementById('kpi-threats-detected'),
            kpiSuspiciousCount: document.getElementById('kpi-suspicious-count'),
            kpiAvgRisk: document.getElementById('kpi-avg-risk'),
            overviewRecentTbody: document.getElementById('overview-recent-tbody'),

            // Investigations
            investigationsSearch: document.getElementById('investigations-search'),
            filterVerdict: document.getElementById('filter-verdict'),
            filterType: document.getElementById('filter-type'),
            investigationsTbody: document.getElementById('investigations-tbody'),
            investigationsEmptyState: document.getElementById('investigations-empty-state'),
            btnExportAllHistory: document.getElementById('btn-export-all-history'),
            btnClearAllHistory: document.getElementById('btn-clear-all-history'),

            // Analytics
            analyticsContainer: document.getElementById('analytics-content-container'),

            // Learn
            urlInspectorInput: document.getElementById('url-inspector-input'),
            urlInspectorOutput: document.getElementById('url-inspector-output'),

            // Settings
            settingsApiKey: document.getElementById('settings-api-key'),
            btnToggleKeyVisibility: document.getElementById('btn-toggle-key-visibility'),
            settingsEngineMode: document.getElementById('settings-engine-mode'),
            btnSaveSettings: document.getElementById('btn-save-settings'),
            btnRemoveApiKey: document.getElementById('btn-remove-api-key'),
            btnWipeAllData: document.getElementById('btn-wipe-all-data'),

            // Modal
            detailModalBackdrop: document.getElementById('detail-modal-backdrop'),
            modalReportId: document.getElementById('modal-report-id'),
            modalReportBody: document.getElementById('modal-report-body'),
            modalCloseBtn: document.getElementById('modal-close-btn')
        };
    }

    bindEvents() {
        // Navigation switching
        document.addEventListener('click', (e) => {
            const targetBtn = e.target.closest('[data-view]');
            if (targetBtn) {
                const view = targetBtn.getAttribute('data-view');
                if (view) this.switchView(view);
            }
        });

        // Theme Toggle
        if (this.dom.themeToggleBtn) {
            this.dom.themeToggleBtn.addEventListener('click', () => this.toggleTheme());
        }

        // Mobile Menu Toggle
        if (this.dom.mobileToggleBtn) {
            this.dom.mobileToggleBtn.addEventListener('click', () => {
                this.dom.sidebar.classList.toggle('mobile-open');
            });
        }

        // Vector Tabs
        if (this.dom.vectorTabBar) {
            this.dom.vectorTabBar.addEventListener('click', (e) => {
                const btn = e.target.closest('.vector-tab-btn');
                if (!btn) return;
                const tab = btn.getAttribute('data-tab');
                if (tab) this.switchVectorTab(tab);
            });
        }

        // Scanner Input Events
        this.dom.artifactInput.addEventListener('input', () => this.handleInputChange());
        this.dom.btnClearInput.addEventListener('click', () => this.clearArtifactInput());
        this.dom.btnExecuteScan.addEventListener('click', () => this.runTriageScan());

        // Keyboard Shortcut: Ctrl/Cmd + Enter to Scan
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                if (this.currentView === 'analyze' && !this.isScanning) {
                    e.preventDefault();
                    this.runTriageScan();
                }
            } else if (e.key === 'Escape') {
                this.closeDetailModal();
            }
        });

        // Investigations Search and Filter
        this.dom.investigationsSearch.addEventListener('input', () => this.renderInvestigations());
        this.dom.filterVerdict.addEventListener('change', () => this.renderInvestigations());
        this.dom.filterType.addEventListener('change', () => this.renderInvestigations());

        // History Export & Clear
        this.dom.btnExportAllHistory.addEventListener('click', () => this.exportAllHistoryJson());
        this.dom.btnClearAllHistory.addEventListener('click', () => this.promptClearHistory());

        // URL Inspector Realtime Input
        this.dom.urlInspectorInput.addEventListener('input', () => this.handleUrlInspectorChange());

        // Settings Actions
        this.dom.btnToggleKeyVisibility.addEventListener('click', () => this.toggleApiKeyVisibility());
        this.dom.btnSaveSettings.addEventListener('click', () => this.saveUserSettings());
        this.dom.btnRemoveApiKey.addEventListener('click', () => this.removeApiKey());
        this.dom.btnWipeAllData.addEventListener('click', () => this.promptWipeAllData());

        // Modal Close
        this.dom.modalCloseBtn.addEventListener('click', () => this.closeDetailModal());
        this.dom.detailModalBackdrop.addEventListener('click', (e) => {
            if (e.target === this.dom.detailModalBackdrop) this.closeDetailModal();
        });
    }

    /* -------------------------------------------------------------------------- */
    /* VIEW ROUTING & THEME                                                       */
    /* -------------------------------------------------------------------------- */

    switchView(viewName) {
        if (!viewName) return;
        this.currentView = viewName;

        // Update active class on nav items
        document.querySelectorAll('.sidebar-nav .nav-item').forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-view') === viewName);
        });

        // Toggle view sections
        this.dom.viewSections.forEach(section => {
            section.classList.toggle('active', section.id === `view-${viewName}`);
        });

        // Update Header Title
        const titles = {
            overview: 'Threat Overview',
            analyze: 'Threat Analysis Workbench',
            investigations: 'Investigation History',
            analytics: 'Session Telemetry',
            learn: 'Threat Encyclopedia',
            settings: 'System Settings'
        };
        this.dom.pageTitle.textContent = titles[viewName] || 'Threat Workbench';

        // Close mobile sidebar if open
        this.dom.sidebar.classList.remove('mobile-open');

        // Trigger view-specific renders
        if (viewName === 'overview') this.renderOverview();
        if (viewName === 'investigations') this.renderInvestigations();
        if (viewName === 'analytics') this.renderAnalytics();
        if (viewName === 'settings') this.loadSettingsForm();
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        storageService.saveSettings({ theme: newTheme });
        this.updateThemeLabel(newTheme);
    }

    applySettingsTheme() {
        const settings = storageService.getSettings();
        const theme = settings.theme || 'dark';
        document.documentElement.setAttribute('data-theme', theme);
        this.updateThemeLabel(theme);
    }

    updateThemeLabel(theme) {
        if (this.dom.themeLabel) {
            this.dom.themeLabel.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
        }
    }

    updateSidebarEngineStatus() {
        const settings = storageService.getSettings();
        const hasKey = Boolean(settings.apiKey && settings.apiKey.trim() !== '');
        const mode = settings.engineMode || 'hybrid';

        let text = 'Heuristic Engine: Ready';
        if (mode === 'deterministic') {
            text = 'Deterministic Mode (Offline)';
        } else if (mode === 'hybrid') {
            text = hasKey ? 'Hybrid Mode (AI Active)' : 'Hybrid Mode (Offline Heuristics)';
        } else if (mode === 'ai_only') {
            text = hasKey ? 'AI Mode (Gemini 2.5)' : 'AI Mode (Key Required)';
        }

        if (this.dom.sidebarEngineModeText) {
            this.dom.sidebarEngineModeText.textContent = text;
        }
    }

    /* -------------------------------------------------------------------------- */
    /* SCANNER WORKBENCH                                                          */
    /* -------------------------------------------------------------------------- */

    switchVectorTab(tabId) {
        if (tabId === this.currentVector) return;
        this.currentVector = tabId;

        this.dom.vectorTabBtns.forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
        });

        const cfg = this.vectorConfigs[tabId] || this.vectorConfigs.url;
        this.dom.inputLabel.textContent = cfg.label;
        this.dom.artifactInput.placeholder = cfg.placeholder;
        this.clearArtifactInput();
        this.renderVectorSamples(tabId);
        this.dom.resultHudContainer.innerHTML = '';
    }

    renderVectorSamples(tabId) {
        const cfg = this.vectorConfigs[tabId] || this.vectorConfigs.url;
        this.dom.sampleChipsContainer.innerHTML = '';

        cfg.samples.forEach(sample => {
            const btn = document.createElement('button');
            btn.className = 'sample-chip';
            btn.textContent = safeTruncate(sample, 40);
            btn.title = sample;
            btn.addEventListener('click', () => {
                this.dom.artifactInput.value = sample;
                this.handleInputChange();
                this.dom.artifactInput.focus();
            });
            this.dom.sampleChipsContainer.appendChild(btn);
        });
    }

    handleInputChange() {
        const len = this.dom.artifactInput.value.length;
        this.dom.charCounter.textContent = `${len} byte${len !== 1 ? 's' : ''}`;
        this.dom.btnClearInput.classList.toggle('visible', len > 0);
    }

    clearArtifactInput() {
        this.dom.artifactInput.value = '';
        this.dom.charCounter.textContent = '0 bytes';
        this.dom.btnClearInput.classList.remove('visible');
        this.dom.artifactInput.focus();
    }

    async runTriageScan() {
        const input = this.dom.artifactInput.value.trim();
        if (!input || this.isScanning) return;

        this.setScanningState(true);
        const settings = storageService.getSettings();
        const mode = settings.engineMode || 'hybrid';
        const apiKey = settings.apiKey;

        try {
            // STEP 1: Input Validation
            await this.updatePipelineStep('VALIDATING INPUT STRUCTURE', 'running');
            await this.sleep(120);

            // STEP 2 & 3: Deterministic Analysis
            await this.updatePipelineStep('EXTRACTING HEURISTIC THREAT VECTORS', 'running');
            const deterministicResult = heuristicEngine.analyze(input, this.currentVector);
            await this.sleep(180);

            // STEP 4: AI Context Synthesis (if applicable)
            let aiResult = null;
            if (mode !== 'deterministic' && apiKey && apiKey.trim() !== '') {
                await this.updatePipelineStep('RUNNING GEMINI 2.5 FLASH THREAT SYNTHESIS', 'running');
                aiResult = await aiThreatService.analyze(input, this.currentVector, deterministicResult, apiKey);
            } else {
                await this.updatePipelineStep('LOCAL HEURISTIC TRIAGE COMPLETE', 'done');
            }

            // STEP 5: Composite Report Generation
            await this.updatePipelineStep('COMPILING THREAT MATRIX & VERDICT', 'running');
            const report = heuristicEngine.generateReport(deterministicResult, aiResult, this.currentVector);
            await this.sleep(120);

            // Complete pipeline
            await this.updatePipelineStep('TRIAGE COMPLETE', 'done');
            this.currentReport = report;

            // Persist scan to local investigation history
            storageService.addScan(report);

            // Render Final HUD
            this.renderResultHud(report);

        } catch (err) {
            console.error('[PhishGuard] Scan error:', err);
            this.renderErrorHud(`Investigation Error: ${err.message}`);
        } finally {
            this.setScanningState(false);
            this.updateSidebarEngineStatus();
        }
    }

    setScanningState(isLoading) {
        this.isScanning = isLoading;
        this.dom.btnExecuteScan.disabled = isLoading;
        this.dom.btnScanText.textContent = isLoading ? 'Triaging Payload...' : 'Execute Threat Scan';
        this.dom.scanPipeline.style.display = isLoading ? 'block' : 'none';
        if (isLoading) {
            this.dom.resultHudContainer.innerHTML = '';
            this.dom.pipelineStepsList.innerHTML = '';
        }
    }

    async updatePipelineStep(stepText, status = 'running') {
        const item = document.createElement('div');
        item.className = `pipeline-step-item ${status}`;
        
        const icon = status === 'done'
            ? `<span style="color:var(--emerald);">✓</span>`
            : `<div class="pipeline-spinner"></div>`;

        item.innerHTML = `${icon}<span>${escapeHtml(stepText)}</span>`;
        this.dom.pipelineStepsList.appendChild(item);
        item.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /* -------------------------------------------------------------------------- */
    /* RESULT HUD RENDERING & EXPLAINABILITY                                      */
    /* -------------------------------------------------------------------------- */

    renderResultHud(r) {
        const vKey = r.verdictKey || 'suspicious';
        const vBannerClass = `banner-${vKey}`;
        const vIconClass = `icon-${vKey}`;
        const scoreClass = `score-${vKey}`;
        const protoClass = `protocol-${vKey}`;

        const icons = {
            safe: '✓',
            suspicious: '!',
            high_risk: '⚠',
            malicious: '✕'
        };

        // Why Reasons Cards
        const whyHtml = (r.whyReasons || []).map(w => {
            return `
                <div class="why-item severity-${escapeHtml(w.severity)}">
                    <span>${escapeHtml(w.title)}</span>
                </div>
            `;
        }).join('');

        // Threat Matrix Table
        const matrixRows = (r.threatMatrix || []).map(m => {
            return `
                <tr>
                    <td style="font-weight:600; color:var(--text-primary);">${escapeHtml(m.category)}</td>
                    <td><span class="matrix-status-pill status-${escapeHtml(m.status)}">${escapeHtml(m.status)}</span></td>
                    <td style="color:var(--text-secondary);">${escapeHtml(m.details)}</td>
                </tr>
            `;
        }).join('');

        const html = `
            <div class="result-hud">
                
                <!-- VERDICT BANNER -->
                <div class="verdict-banner ${vBannerClass}">
                    <div class="verdict-primary-info">
                        <div class="verdict-icon-container ${vIconClass}">
                            ${icons[vKey] || '•'}
                        </div>
                        <div>
                            <div class="verdict-title" style="color: var(--${escapeHtml(r.verdictColor)});">
                                ${escapeHtml(r.verdict)}
                            </div>
                            <div class="verdict-summary-text">
                                ${escapeHtml(r.summary)}
                            </div>
                        </div>
                    </div>

                    <div class="risk-meter-widget">
                        <div class="risk-meter-score ${scoreClass}">${r.riskScore}<span style="font-size:1.2rem; color:var(--text-muted);">/100</span></div>
                        <div class="risk-meter-label">Threat Index &middot; ${escapeHtml(r.confidence)} Conf.</div>
                    </div>
                </div>

                <!-- HUD BODY -->
                <div class="result-body">
                    
                    <!-- WHY SECTION -->
                    <div>
                        <div class="hud-section-title">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                            <span>Key Findings & Rationale ("Why?")</span>
                        </div>
                        <div class="why-card-grid">
                            ${whyHtml}
                        </div>
                    </div>

                    <!-- THREAT MATRIX -->
                    ${matrixRows ? `
                    <div>
                        <div class="hud-section-title">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>
                            <span>Multi-Vector Threat Matrix</span>
                        </div>
                        <div class="investigations-table-container">
                            <table class="threat-matrix-table">
                                <thead>
                                    <tr>
                                        <th style="width: 25%;">Vector Category</th>
                                        <th style="width: 15%;">Status</th>
                                        <th>Technical Evidence</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${matrixRows}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    ` : ''}

                    <!-- ACTION PROTOCOL -->
                    <div class="action-protocol-card ${protoClass}">
                        <div class="action-protocol-title">Recommended SOC & User Action Protocol:</div>
                        <div class="action-protocol-text">${escapeHtml(r.recommendation)}</div>
                    </div>

                    <!-- IOC / ARTIFACT DRAWER -->
                    <div>
                        <div class="hud-section-title">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                            <span>Target Artifact & Triage Metadata</span>
                        </div>
                        <div class="ioc-drawer">
                            <div style="display:flex; justify-content:space-between; margin-bottom:0.5rem; font-size:0.75rem; color:var(--text-muted); font-family:var(--font-mono);">
                                <span>ID: ${escapeHtml(r.id)} &middot; ${escapeHtml(r.timestamp)}</span>
                                <span>Engine: ${escapeHtml(r.engineInfo?.aiEngine || 'Deterministic')}</span>
                            </div>
                            <pre class="ioc-code-block">${escapeHtml(r.input)}</pre>
                        </div>
                    </div>

                    <!-- ACTIONS / EXPORT TOOLBAR -->
                    <div class="result-footer-actions">
                        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                            <button class="btn-sm" id="btn-copy-iocs">Copy IOCs</button>
                            <button class="btn-sm" id="btn-export-json">Export JSON</button>
                            <button class="btn-sm" id="btn-export-md">Export Markdown</button>
                            <button class="btn-sm" id="btn-print-report">Print Report</button>
                        </div>
                        <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">PhishGuard Heuristic Matrix v3.0</span>
                    </div>

                </div>
            </div>
        `;

        this.dom.resultHudContainer.innerHTML = html;
        this.dom.resultHudContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        // Bind result buttons
        document.getElementById('btn-copy-iocs')?.addEventListener('click', () => {
            const iocText = `[PHISHGUARD IOC REPORT]\nTarget: ${r.input}\nVerdict: ${r.verdict} (Risk: ${r.riskScore}/100)\nID: ${r.id}\nIndicators:\n${(r.indicators || []).map(i => `• ${i.title}`).join('\n')}`;
            copyToClipboard(iocText);
            const btn = document.getElementById('btn-copy-iocs');
            if (btn) btn.textContent = 'Copied!';
            setTimeout(() => { if (btn) btn.textContent = 'Copy IOCs'; }, 1500);
        });

        document.getElementById('btn-export-json')?.addEventListener('click', () => ReportExporter.exportAsJson(r));
        document.getElementById('btn-export-md')?.addEventListener('click', () => ReportExporter.exportAsMarkdown(r));
        document.getElementById('btn-print-report')?.addEventListener('click', () => ReportExporter.printReport());
    }

    renderErrorHud(msg) {
        this.dom.resultHudContainer.innerHTML = `
            <div style="margin-top:2rem; padding:1.5rem; background:var(--crimson-dim); border:1px solid var(--crimson-border); border-radius:var(--radius-md); color:var(--crimson); font-family:var(--font-mono); font-size:0.9rem;">
                <strong>[TERMINATED]</strong> ${escapeHtml(msg)}
            </div>
        `;
    }

    /* -------------------------------------------------------------------------- */
    /* OVERVIEW & INVESTIGATIONS VIEW                                             */
    /* -------------------------------------------------------------------------- */

    renderOverview() {
        const history = storageService.getHistory();
        const metrics = AnalyticsEngine.computeMetrics(history);

        this.dom.kpiTotalScans.textContent = metrics.totalScans;
        this.dom.kpiThreatsDetected.textContent = metrics.threatsDetected;
        this.dom.kpiSuspiciousCount.textContent = metrics.suspiciousCount;
        this.dom.kpiAvgRisk.innerHTML = `${metrics.averageRisk}<span style="font-size: 1rem; color: var(--text-muted);">/100</span>`;

        // Render Recent Table (up to 5 items)
        const recent = history.slice(0, 5);
        if (recent.length === 0) {
            this.dom.overviewRecentTbody.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align:center; color:var(--text-muted); padding: 2rem;">No recent investigations. Execute a scan from the Analyzer.</td>
                </tr>
            `;
            return;
        }

        this.dom.overviewRecentTbody.innerHTML = recent.map(h => {
            const vKey = (h.verdictKey || h.verdict || 'suspicious').toLowerCase().replace(/\s+/g, '_');
            return `
                <tr style="cursor: pointer;" data-open-id="${escapeHtml(h.id)}">
                    <td><span class="badge-verdict badge-${vKey}">${escapeHtml(h.verdict)}</span></td>
                    <td style="font-family: var(--font-mono);">${escapeHtml(safeTruncate(h.input, 50))}</td>
                    <td style="text-transform: uppercase; font-size: 0.75rem;">${escapeHtml(h.artifactType)}</td>
                    <td style="font-family: var(--font-mono); font-weight: 700;">${h.riskScore}/100</td>
                    <td style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(h.timestamp.split('T')[0] || h.timestamp)}</td>
                </tr>
            `;
        }).join('');

        this.dom.overviewRecentTbody.querySelectorAll('[data-open-id]').forEach(row => {
            row.addEventListener('click', () => {
                const id = row.getAttribute('data-open-id');
                this.openDetailModalById(id);
            });
        });
    }

    renderInvestigations() {
        const query = this.dom.investigationsSearch.value.toLowerCase().trim();
        const verdictFilter = this.dom.filterVerdict.value;
        const typeFilter = this.dom.filterType.value;

        const history = storageService.getHistory();
        const filtered = history.filter(h => {
            const matchQuery = !query || 
                (h.input && h.input.toLowerCase().includes(query)) ||
                (h.id && h.id.toLowerCase().includes(query)) ||
                (h.summary && h.summary.toLowerCase().includes(query)) ||
                (h.indicators && h.indicators.some(i => i.title.toLowerCase().includes(query)));

            const matchVerdict = verdictFilter === 'ALL' || (h.verdictKey || '').toUpperCase() === verdictFilter || (h.verdict || '').toUpperCase() === verdictFilter;
            const matchType = typeFilter === 'ALL' || (h.artifactType || '').toLowerCase() === typeFilter;

            return matchQuery && matchVerdict && matchType;
        });

        if (filtered.length === 0) {
            this.dom.investigationsTbody.innerHTML = '';
            this.dom.investigationsEmptyState.style.display = 'block';
            return;
        }

        this.dom.investigationsEmptyState.style.display = 'none';
        this.dom.investigationsTbody.innerHTML = filtered.map(h => {
            const vKey = (h.verdictKey || h.verdict || 'suspicious').toLowerCase().replace(/\s+/g, '_');
            return `
                <tr>
                    <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--cyan);">${escapeHtml(h.id)}</td>
                    <td><span class="badge-verdict badge-${vKey}">${escapeHtml(h.verdict)}</span></td>
                    <td style="font-family: var(--font-mono); cursor:pointer;" data-detail-id="${escapeHtml(h.id)}">${escapeHtml(safeTruncate(h.input, 45))}</td>
                    <td style="text-transform: uppercase; font-size: 0.75rem;">${escapeHtml(h.artifactType)}</td>
                    <td style="font-family: var(--font-mono); font-weight: 700;">${h.riskScore}/100</td>
                    <td style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(h.timestamp.split('T')[0] || h.timestamp)}</td>
                    <td>
                        <button class="btn-sm" data-view-id="${escapeHtml(h.id)}" style="padding: 2px 6px; font-size: 0.75rem;">Inspect</button>
                        <button class="btn-sm" data-delete-id="${escapeHtml(h.id)}" style="padding: 2px 6px; font-size: 0.75rem; color: var(--crimson);">✕</button>
                    </td>
                </tr>
            `;
        }).join('');

        // Bind inspection and deletion handlers
        this.dom.investigationsTbody.querySelectorAll('[data-view-id], [data-detail-id]').forEach(el => {
            el.addEventListener('click', () => {
                const id = el.getAttribute('data-view-id') || el.getAttribute('data-detail-id');
                this.openDetailModalById(id);
            });
        });

        this.dom.investigationsTbody.querySelectorAll('[data-delete-id]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const id = btn.getAttribute('data-delete-id');
                storageService.deleteScan(id);
                this.renderInvestigations();
                this.renderOverview();
            });
        });
    }

    openDetailModalById(id) {
        const history = storageService.getHistory();
        const report = history.find(h => h.id === id);
        if (!report) return;

        this.dom.modalReportId.textContent = `Investigation ${report.id}`;
        
        const indicatorsHtml = (report.indicators || []).map(i => `
            <div style="padding:0.5rem 0.75rem; background:var(--bg-surface-raised); border-radius:var(--radius-xs); margin-bottom:0.4rem; font-size:0.8rem;">
                <span style="font-weight:700; color:var(--${i.severity === 'danger' ? 'crimson' : i.severity === 'warning' ? 'amber' : 'cyan'});">[${escapeHtml(i.severity.toUpperCase())}]</span>
                <span style="color:var(--text-primary); font-weight:600;"> ${escapeHtml(i.title)}</span>
                <p style="color:var(--text-secondary); margin-top:0.2rem; font-size:0.75rem;">${escapeHtml(i.description)}</p>
            </div>
        `).join('');

        this.dom.modalReportBody.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                <div>
                    <span class="badge-verdict badge-${escapeHtml(report.verdictKey || 'suspicious')}">${escapeHtml(report.verdict)}</span>
                    <span style="font-size:0.8rem; color:var(--text-muted); margin-left:0.5rem;">${escapeHtml(report.timestamp)}</span>
                </div>
                <div style="font-family:var(--font-mono); font-size:1.5rem; font-weight:800; color:var(--${escapeHtml(report.verdictColor || 'amber')});">${report.riskScore}/100</div>
            </div>

            <div style="margin-bottom:1rem;">
                <div style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; margin-bottom:0.25rem;">Target Payload (${escapeHtml(report.artifactType.toUpperCase())})</div>
                <pre class="ioc-code-block" style="padding:0.75rem; background:var(--bg-input); border-radius:var(--radius-xs);">${escapeHtml(report.input)}</pre>
            </div>

            <div style="margin-bottom:1rem;">
                <div style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; margin-bottom:0.25rem;">Executive Summary</div>
                <p style="font-size:0.85rem; color:var(--text-secondary);">${escapeHtml(report.summary)}</p>
            </div>

            <div style="margin-bottom:1rem;">
                <div style="font-size:0.75rem; text-transform:uppercase; color:var(--text-muted); font-weight:700; margin-bottom:0.25rem;">Identified Threat Vectors (${(report.indicators || []).length})</div>
                ${indicatorsHtml || '<p style="font-size:0.8rem; color:var(--text-muted);">No negative vector flags identified.</p>'}
            </div>

            <div style="display:flex; justify-content:flex-end; gap:0.5rem; margin-top:1.5rem; border-top:1px solid var(--border-subtle); padding-top:1rem;">
                <button class="btn-sm" id="btn-modal-export-json">Export JSON</button>
                <button class="btn-sm" id="btn-modal-export-md">Export Markdown</button>
                <button class="btn-sm btn-primary" id="btn-modal-rescan">Load in Analyzer</button>
            </div>
        `;

        document.getElementById('btn-modal-export-json')?.addEventListener('click', () => ReportExporter.exportAsJson(report));
        document.getElementById('btn-modal-export-md')?.addEventListener('click', () => ReportExporter.exportAsMarkdown(report));
        document.getElementById('btn-modal-rescan')?.addEventListener('click', () => {
            this.closeDetailModal();
            this.switchVectorTab(report.artifactType);
            this.dom.artifactInput.value = report.input;
            this.handleInputChange();
            this.switchView('analyze');
        });

        this.dom.detailModalBackdrop.classList.add('open');
    }

    closeDetailModal() {
        this.dom.detailModalBackdrop.classList.remove('open');
    }

    exportAllHistoryJson() {
        const history = storageService.getHistory();
        const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `PhishGuard_All_Investigations_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    promptClearHistory() {
        if (confirm('Are you sure you want to purge all local investigation records? This cannot be undone.')) {
            storageService.clearHistory();
            this.renderInvestigations();
            this.renderOverview();
        }
    }

    /* -------------------------------------------------------------------------- */
    /* ANALYTICS VIEW (GENUINE DATA ONLY)                                         */
    /* -------------------------------------------------------------------------- */

    renderAnalytics() {
        const history = storageService.getHistory();
        const metrics = AnalyticsEngine.computeMetrics(history);

        if (!metrics.hasData) {
            this.dom.analyticsContainer.innerHTML = `
                <div class="empty-state-box">
                    <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                    <h4 class="empty-state-title">Insufficient Telemetry Data</h4>
                    <p class="empty-state-desc">Session analytics require at least one triaged artifact. Run investigations in the Analyzer to dynamically compute threat distributions.</p>
                    <button class="btn-sm btn-primary" data-view="analyze">Start First Investigation</button>
                </div>
            `;
            return;
        }

        const v = metrics.verdictDistribution;
        const vectorsList = metrics.topAttackVectors.map(vec => `
            <div style="display:flex; justify-content:space-between; align-items:center; padding:0.6rem 0.8rem; background:var(--bg-surface-raised); border-radius:var(--radius-xs); font-size:0.85rem;">
                <span style="font-weight:600; color:var(--text-primary);">${escapeHtml(vec.name)}</span>
                <span style="font-family:var(--font-mono); color:var(--cyan); font-weight:700;">${vec.count} occurrences (${vec.percentage}%)</span>
            </div>
        `).join('');

        this.dom.analyticsContainer.innerHTML = `
            <div class="kpi-grid">
                <div class="kpi-card">
                    <div class="kpi-title">Safe vs Threat Ratio</div>
                    <div class="kpi-value" style="font-size:1.6rem; margin-top:0.5rem;">
                        <span style="color:var(--emerald);">${metrics.safeCount} Safe</span> &middot; <span style="color:var(--crimson);">${metrics.threatsDetected} Threats</span>
                    </div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Highest Threat Vector</div>
                    <div class="kpi-value" style="font-size:1.3rem; margin-top:0.5rem; color:var(--amber);">
                        ${escapeHtml(metrics.topAttackVectors[0]?.name || 'None')}
                    </div>
                </div>
                <div class="kpi-card">
                    <div class="kpi-title">Artifact Coverage</div>
                    <div class="kpi-value" style="font-size:1.1rem; margin-top:0.5rem; color:var(--text-secondary); font-family:var(--font-mono);">
                        URL: ${metrics.artifactDistribution.url} | SMS: ${metrics.artifactDistribution.message} | Email: ${metrics.artifactDistribution.email} | APK: ${metrics.artifactDistribution.apk}
                    </div>
                </div>
            </div>

            <!-- Threat Distribution Graph -->
            <div style="background:var(--bg-surface); border:1px solid var(--border-subtle); border-radius:var(--radius-md); padding:1.5rem; margin-bottom:1.5rem;">
                <h3 style="font-size:1rem; font-weight:700; margin-bottom:1rem;">Verdict Risk Distribution</h3>
                <div style="height:24px; display:flex; border-radius:var(--radius-xs); overflow:hidden; background:var(--bg-surface-raised);">
                    <div style="width:${v.safe}%; background:var(--emerald);" title="Safe: ${v.safe}%"></div>
                    <div style="width:${v.suspicious}%; background:var(--amber);" title="Suspicious: ${v.suspicious}%"></div>
                    <div style="width:${v.highRisk}%; background:#ea580c;" title="High Risk: ${v.highRisk}%"></div>
                    <div style="width:${v.malicious}%; background:var(--crimson);" title="Malicious: ${v.malicious}%"></div>
                </div>
                <div style="display:flex; justify-content:space-between; margin-top:0.75rem; font-size:0.75rem; font-family:var(--font-mono);">
                    <span style="color:var(--emerald);">● Safe (${v.safe}%)</span>
                    <span style="color:var(--amber);">● Suspicious (${v.suspicious}%)</span>
                    <span style="color:#ea580c;">● High Risk (${v.highRisk}%)</span>
                    <span style="color:var(--crimson);">● Malicious (${v.malicious}%)</span>
                </div>
            </div>

            <!-- Top Attack Vectors -->
            <div style="background:var(--bg-surface); border:1px solid var(--border-subtle); border-radius:var(--radius-md); padding:1.5rem;">
                <h3 style="font-size:1rem; font-weight:700; margin-bottom:1rem;">Top Identified Attack Vectors (Session)</h3>
                <div style="display:flex; flex-direction:column; gap:0.5rem;">
                    ${vectorsList || '<p style="color:var(--text-muted); font-size:0.8rem;">No attack vectors recorded.</p>'}
                </div>
            </div>
        `;
    }

    /* -------------------------------------------------------------------------- */
    /* LEARN & LIVE URL INSPECTOR                                                 */
    /* -------------------------------------------------------------------------- */

    initUrlInspector() {
        this.dom.urlInspectorInput.value = 'https://user:auth@secure-verify.bank-login.ru:8080/auth/login?token=abc#anchor';
        this.handleUrlInspectorChange();
    }

    handleUrlInspectorChange() {
        const val = this.dom.urlInspectorInput.value.trim();
        if (!val) {
            this.dom.urlInspectorOutput.innerHTML = '';
            return;
        }

        const analysis = analyzeUrl(val);
        const a = analysis.parsedAnatomy || {};

        this.dom.urlInspectorOutput.innerHTML = `
            <div class="decoder-part-box">
                <div class="decoder-part-label">Protocol Scheme</div>
                <div class="decoder-part-val">${escapeHtml(a.protocol || 'None')}</div>
            </div>
            <div class="decoder-part-box">
                <div class="decoder-part-label">Hostname</div>
                <div class="decoder-part-val">${escapeHtml(a.hostname || 'None')}</div>
            </div>
            <div class="decoder-part-box">
                <div class="decoder-part-label">Top-Level Domain (TLD)</div>
                <div class="decoder-part-val">${escapeHtml(a.tld || 'None')}</div>
            </div>
            <div class="decoder-part-box">
                <div class="decoder-part-label">Port</div>
                <div class="decoder-part-val">${escapeHtml(String(a.port || 'Default'))}</div>
            </div>
            <div class="decoder-part-box">
                <div class="decoder-part-label">Pathname</div>
                <div class="decoder-part-val">${escapeHtml(a.pathname || '/')}</div>
            </div>
            <div class="decoder-part-box">
                <div class="decoder-part-label">Query Search Params</div>
                <div class="decoder-part-val">${escapeHtml(a.search || 'None')}</div>
            </div>
            <div class="decoder-part-box">
                <div class="decoder-part-label">Shannon Domain Entropy</div>
                <div class="decoder-part-val" style="color:var(--cyan);">${a.entropy || 0} bits/char</div>
            </div>
            <div class="decoder-part-box">
                <div class="decoder-part-label">Heuristic Risk Score</div>
                <div class="decoder-part-val" style="color:var(--${analysis.calculatedScore > 50 ? 'crimson' : analysis.calculatedScore > 20 ? 'amber' : 'emerald'});">${analysis.calculatedScore}/100</div>
            </div>
        `;
    }

    /* -------------------------------------------------------------------------- */
    /* SETTINGS & BYOK                                                            */
    /* -------------------------------------------------------------------------- */

    loadSettingsForm() {
        const settings = storageService.getSettings();
        this.dom.settingsApiKey.value = settings.apiKey || '';
        this.dom.settingsEngineMode.value = settings.engineMode || 'hybrid';
    }

    toggleApiKeyVisibility() {
        const type = this.dom.settingsApiKey.type === 'password' ? 'text' : 'password';
        this.dom.settingsApiKey.type = type;
        this.dom.btnToggleKeyVisibility.textContent = type === 'password' ? 'Show' : 'Hide';
    }

    saveUserSettings() {
        const apiKey = this.dom.settingsApiKey.value.trim();
        const engineMode = this.dom.settingsEngineMode.value;

        storageService.saveSettings({ apiKey, engineMode });
        this.updateSidebarEngineStatus();
        alert('Settings saved successfully.');
    }

    removeApiKey() {
        this.dom.settingsApiKey.value = '';
        storageService.saveSettings({ apiKey: '' });
        this.updateSidebarEngineStatus();
        alert('API Key removed. Engine reverted to 100% offline deterministic mode.');
    }

    promptWipeAllData() {
        if (confirm('CRITICAL: This will erase all scan history, saved API keys, and custom preferences from your browser. Proceed?')) {
            storageService.wipeAllData();
            this.loadSettingsForm();
            this.updateSidebarEngineStatus();
            this.renderOverview();
            alert('All local storage data has been purged.');
        }
    }
}

// Instantiate Application on DOM Load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.PhishGuard = new PhishGuardApp();
        window.PhishGuard.init();
    });
} else {
    window.PhishGuard = new PhishGuardApp();
    window.PhishGuard.init();
}