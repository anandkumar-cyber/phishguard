/**
 * Test Runner Script (Node.js & CLI compatible)
 */

import { runEngineTests } from './engine.test.js';

console.log('🛡️  [PhishGuard] Initializing Threat Engine Unit & Security Test Suite...\n');

const startTime = performance.now();
const results = runEngineTests();
const duration = (performance.now() - startTime).toFixed(2);

console.log('\n======================================================');
console.log(`📊 TEST RESULTS: ${results.passed}/${results.total} PASSED (${duration}ms)`);
console.log('======================================================');

if (results.failed === 0) {
    console.log(`✅ All ${results.total} deterministic heuristic and security regression tests passed!\n`);
    if (typeof process !== 'undefined' && process.exit) {
        process.exit(0);
    }
} else {
    console.error(`❌ ${results.failed} tests failed! Review logs above.\n`);
    if (typeof process !== 'undefined' && process.exit) {
        process.exit(1);
    }
}

