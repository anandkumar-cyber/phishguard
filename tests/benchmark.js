/**
 * Reproducible Performance Benchmarking Suite for PhishGuard Deterministic Heuristic Engine
 */

import { heuristicEngine } from '../src/engine/HeuristicEngine.js';

const BENCHMARK_PAYLOADS = [
    { type: 'url', input: 'http://paypa1-security-login.ru/verify?token=98234' },
    { type: 'url', input: 'https://google.com/search?q=cybersecurity+threat+intelligence' },
    { type: 'url', input: 'https://xn--pple-43d.com/login' },
    { type: 'url', input: 'https://legit-portal.com@evil-phish-domain.top/auth' },
    { type: 'message', input: 'URGENT: Your SBI account has been locked due to missing KYC. Update immediately at http://sbi-secure.ru/verify within 24 hours.' },
    { type: 'message', input: 'Hi Anand, the team sync is scheduled for 3 PM today in Conference Room B.' },
    { type: 'email', input: 'From: "PayPal Security" <billing-alert98@gmail.com>\nSubject: Action Required: Your account is suspended\n\nPlease verify your credentials at http://paypal-reauth.xyz' },
    { type: 'apk', input: 'com.whatsapp.update.pro.free.unlimited' },
    { type: 'apk', input: 'com.google.android.youtube' }
];

console.log('⏱️  [PhishGuard] Starting Deterministic Engine Performance Benchmark...\n');

const ITERATIONS = 1000;
const times = [];

const globalStart = performance.now();

for (let i = 0; i < ITERATIONS; i++) {
    const payload = BENCHMARK_PAYLOADS[i % BENCHMARK_PAYLOADS.length];
    const t0 = performance.now();
    const result = heuristicEngine.analyze(payload.input, payload.type);
    heuristicEngine.generateReport(result, null, payload.type);
    const t1 = performance.now();
    times.push(t1 - t0);
}

const totalDuration = performance.now() - globalStart;
const minTime = Math.min(...times);
const maxTime = Math.max(...times);
const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
const throughput = Math.round((ITERATIONS / totalDuration) * 1000);

console.log('======================================================');
console.log(`🚀 BENCHMARK RESULTS (${ITERATIONS} Sequential Triage Runs):`);
console.log('======================================================');
console.log(`• Total Execution Time : ${totalDuration.toFixed(2)} ms`);
console.log(`• Average Triage Time  : ${avgTime.toFixed(4)} ms / artifact`);
console.log(`• Minimum Triage Time  : ${minTime.toFixed(4)} ms`);
console.log(`• Maximum Triage Time  : ${maxTime.toFixed(4)} ms`);
console.log(`• Throughput           : ~${throughput.toLocaleString()} analyses / sec`);
console.log('======================================================\n');

