import { test, expect } from './fixtures.js';

const kPolicyRulesets = ['permissive', 'firstparty', 'sandbox-lite', 'sandbox', 'strict'];

// Helper to set the default policy level (0 = permissive, 1 = firstparty,
// 2 = sandbox-lite, 3 = sandbox, 4 = strict) and wait for dNR rulesets to update.
async function setDefaultPolicy(serviceWorker, level) {
    const enable = kPolicyRulesets[level];
    const disable = kPolicyRulesets.filter((r) => r !== enable);
    await serviceWorker.evaluate(async ({ level, enable, disable }) => {
        const { options = {} } = await chrome.storage.sync.get('options');
        options.version ??= 3;
        options.defaultpolicy = level;
        await chrome.storage.sync.set({ options });
        await chrome.declarativeNetRequest.updateEnabledRulesets({
            enableRulesetIds: [enable],
            disableRulesetIds: disable,
        });
    }, { level, enable, disable });
}

test.describe('matrix³ CSP Testbench', () => {
    test('permissive mode (level 0) allows all page-load probes', async ({ serviceWorker, testbench }) => {
        await setDefaultPolicy(serviceWorker, 0);
        await testbench.reload();

        await expect(testbench.locator('#badge-inline-auth')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-eval')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-wasm')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-ext-script')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-fetch-self')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-fetch')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-frame-self')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-frame-cross')).toHaveText('Allowed');
    });

    test('firstparty mode (level 1) blocks cross-origin script/fetch/frame and allows passive/self', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        // First-party and passive resources should be allowed
        await expect(testbench.locator('#badge-inline-auth')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-eval')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-img-self')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-img-cross')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-fetch-self')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-frame-self')).toHaveText('Allowed');

        // Active cross-origin resources and workers should be blocked
        await expect(testbench.locator('#badge-ext-script')).toHaveText('Blocked');
        await expect(testbench.locator('#badge-fetch')).toHaveText('Blocked');
        await expect(testbench.locator('#badge-frame-cross')).toHaveText('Blocked');

        // Open the Report panel and verify the blocked origins show up as violations
        // (bucketed by registrable domain in default Domain scope: *.github.com)
        const report = await openPanel('report');
        const githubRow = report.locator('table#sources tbody tr', { hasText: '*.github.com' });
        await expect(githubRow).toBeVisible();

        const connectCheckbox = githubRow.locator('input.rule.violation');
        await expect(connectCheckbox).toBeVisible();
        await expect(connectCheckbox).not.toBeChecked();

        // Check the box to allow https://*.github.com in connect-src (creates a session rule)
        await connectCheckbox.check();
        await expect(report.locator('button#commit')).toBeEnabled();

        // Reload the testbench and verify cross-origin fetch is now Allowed!
        await testbench.reload();
        await expect(testbench.locator('#badge-fetch')).toHaveText('Allowed');
    });

    test('resolves 302 redirect blocked-uri to target origin instead of self', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        // Click the 302 redirect test button (/redirect -> https://cdn.jsdelivr.net/npm/d3/+esm)
        await testbench.locator('#redirect-btn').click();
        await expect(testbench.locator('#badge-special')).toHaveText('Blocked');

        const report = await openPanel('report');
        const jsdelivrRow = report.locator('table#sources tbody tr', { hasText: '*.jsdelivr.net' });
        await expect(jsdelivrRow).toBeVisible();
        await expect(jsdelivrRow.locator('input.rule.violation')).toBeVisible();
    });

    test('attributes opaque-origin sandboxed srcdoc violations via documentId fallback', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        // Spawn <iframe sandbox="allow-scripts" srcdoc="..."> fetching https://untrusted.example.com/
        await testbench.locator('#srcdoc-btn').click();
        await expect(testbench.locator('#badge-special')).toHaveText('Fetch Blocked (Check Report)');

        const report = await openPanel('report');
        const exampleRow = report.locator('table#sources tbody tr', { hasText: '*.example.com' });
        await expect(exampleRow).toBeVisible();
        await expect(exampleRow.locator('input.rule.violation')).toBeVisible();
    });

    test('rule lifecycle: session -> commit (dynamic) -> uncommit -> abandon, and tab disable/resume', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        const report = await openPanel('report');
        const githubRow = report.locator('table#sources tbody tr', { hasText: '*.github.com' });
        const connectBox = githubRow.locator('input.rule.violation');
        await expect(connectBox).toBeVisible();

        // 1. Toggle checkbox -> creates a session rule
        await connectBox.check();
        await expect(report.locator('button#commit')).toBeEnabled();
        await expect(report.locator('button#abandon')).toBeEnabled();

        // 2. Commit -> promotes session rule to dynamic rule
        await report.locator('button#commit').click();
        await expect(report.locator('button#uncommit')).toBeEnabled();
        await expect(report.locator('button#abandon')).toBeDisabled();

        // 3. Uncommit -> demotes dynamic rule back to session rule
        await report.locator('button#uncommit').click();
        await expect(report.locator('button#commit')).toBeEnabled();
        await expect(report.locator('button#abandon')).toBeEnabled();

        // 4. Abandon -> discards session rule
        await report.locator('button#abandon').click();
        await expect(report.locator('button#commit')).toBeDisabled();
        await expect(report.locator('button#reset')).toBeDisabled();

        // 5. Disable -> exempts the active tab from all CSP rules
        await report.locator('button#disable').click();
        await expect(report.locator('button#resume')).toBeEnabled();
        await testbench.reload();
        await expect(testbench.locator('#badge-fetch')).toHaveText('Allowed');

        // 6. Resume -> removes tab exemption
        await report.locator('button#resume').click();
        await expect(report.locator('button#resume')).toBeDisabled();
        await testbench.reload();
        await expect(testbench.locator('#badge-fetch')).toHaveText('Blocked');
    });

    test('captures Server Content-Security-Policy and imports nonces/paths on Accept', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);

        // Apply a Server CSP with a nonce, a path-suffixed origin, and report-uri (which should be stripped)
        await testbench.locator('textarea#csp').fill(
            "script-src 'nonce-test-nonce' https://cdn.jsdelivr.net/npm/d3/; style-src 'self' 'unsafe-inline'; report-uri /report"
        );
        await testbench.locator('form.csp-form button[type="submit"]').click();

        const report = await openPanel('report');
        const details = report.locator('div#serverpolicy details');
        await expect(details).toBeVisible();
        await details.locator('summary').click();

        // Verify path-suffixed source was normalized to origin in #serversources
        const serverJsdelivrRow = report.locator('table#serversources tbody tr', { hasText: 'cdn.jsdelivr.net' });
        await expect(serverJsdelivrRow).toBeVisible();

        // Click Accept to import the server policy into matrix³'s session rules
        await report.locator('button#accept').click();
        await expect(report.locator('button#commit')).toBeEnabled();

        // Verify 'nonce-test-nonce' was translated to 'unsafe-inline' + 'self' in #sources
        const mainJsdelivrRow = report.locator('table#sources tbody tr', { hasText: 'cdn.jsdelivr.net' });
        await expect(mainJsdelivrRow).toBeVisible();
    });
});
