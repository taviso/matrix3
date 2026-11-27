import {
    test,
    expect,
    setDefaultPolicy,
    waitForPanelIdle,
    getOnloadBadges,
    getReportedViolations,
    getSourceCheckbox,
} from './fixtures.js';

test.describe('Default Policy Modes (0..4) & Page-Load Probes', () => {
    test('mode 0 (permissive): allows all 21 page-load probes with zero violations', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 0);
        await testbench.reload();

        const badges = await getOnloadBadges(testbench);
        expect(badges).toEqual({
            'inline-auth': 'Allowed',
            'inline-plain': 'Allowed',
            'eval': 'Allowed',
            'wasm': 'Allowed',
            'ext-script': 'Allowed',
            'inline-style': 'Allowed',
            'ext-style': 'Allowed',
            'img-self': 'Allowed',
            'img-cross': 'Allowed',
            'img-data': 'Allowed',
            'font-self': 'Allowed',
            'font-cross': 'Allowed',
            'font-data': 'Allowed',
            'media-self': 'Allowed',
            'media-cross': 'Allowed',
            'media-data': 'Allowed',
            'fetch-self': 'Allowed',
            'fetch': 'Allowed',
            'frame-self': 'Allowed',
            'frame-cross': 'Allowed',
            'object-self': 'Allowed',
        });

        const report = await openPanel('report');
        const violations = await getReportedViolations(report);
        expect(violations).toEqual({});
    });

    test('mode 1 (firstparty): allows first-party/passive probes, blocks cross-origin active probes, and reports exact violations', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        const badges = await getOnloadBadges(testbench);
        expect(badges).toEqual({
            'inline-auth': 'Allowed',
            'inline-plain': 'Allowed',
            'eval': 'Allowed',
            'wasm': 'Allowed',
            'ext-script': 'Blocked',
            'inline-style': 'Allowed',
            'ext-style': 'Allowed',
            'img-self': 'Allowed',
            'img-cross': 'Allowed',
            'img-data': 'Allowed',
            'font-self': 'Allowed',
            'font-cross': 'Allowed',
            'font-data': 'Allowed',
            'media-self': 'Allowed',
            'media-cross': 'Blocked',
            'media-data': 'Blocked',
            'fetch-self': 'Allowed',
            'fetch': 'Blocked',
            'frame-self': 'Allowed',
            'frame-cross': 'Blocked',
            'object-self': 'Allowed',
        });

        const report = await openPanel('report');
        await expect.poll(() => getReportedViolations(report)).toEqual({
            'data:': ['media-src'],
            'https://*.github.com': ['connect-src'],
            'https://*.google.com': ['script-src', 'media-src'],
            'https://example.com': ['frame-src', 'manifest-src'],
        });
    });

    test('mode 2 (sandbox-lite): enforces opaque origin with allow-scripts and allow-forms', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 2);
        await testbench.reload();

        // Document runs in a unique opaque origin ("null") with scripts allowed
        expect(await testbench.evaluate(() => window.origin)).toBe('null');
        await expect(testbench.locator('#badge-inline-auth')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-inline-plain')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-eval')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-inline-style')).toHaveText('Allowed');
        await expect(testbench.locator('#badge-img-data')).toHaveText('Allowed');

        const report = await openPanel('report');
        await expect(report.locator('input#sandbox-enabled')).toBeChecked();
        await expect(report.locator('input#allow-scripts')).toBeChecked();
        await expect(report.locator('input#allow-forms')).toBeChecked();
        await expect(report.locator('input#allow-same-origin')).not.toBeChecked();
    });

    test('mode 3 (sandbox): blocks all script execution via bare sandbox directive', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 3);
        await testbench.reload();

        // Scripts do not execute at all under bare sandbox, so initial HTML badges remain "Blocked"
        await expect(testbench.locator('#badge-inline-auth')).toHaveText('Blocked');
        await expect(testbench.locator('#badge-inline-plain')).toHaveText('Blocked');
        await expect(testbench.locator('#badge-eval')).toHaveText('Blocked');
        await expect(testbench.locator('#badge-wasm')).toHaveText('Blocked');

        const report = await openPanel('report');
        await expect(report.locator('input#sandbox-enabled')).toBeChecked();
        await expect(report.locator('input#allow-scripts')).not.toBeChecked();
        await expect(report.locator('input#allow-forms')).not.toBeChecked();
    });

    test('mode 4 (strict): blocks scripts, frames, objects, and third-party assets while allowing self/data images', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 4);
        await testbench.reload();

        // Even inline scripts are blocked in strict mode (default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:)
        await expect(testbench.locator('#badge-inline-auth')).toHaveText('Blocked');
        await expect(testbench.locator('#badge-inline-plain')).toHaveText('Blocked');
        await expect(testbench.locator('#badge-eval')).toHaveText('Blocked');

        // Verify passive image enforcement directly via naturalWidth
        const imgStates = await testbench.evaluate(() => ({
            self: document.querySelector('img[data-probe="img-self"]')?.naturalWidth > 0,
            data: document.querySelector('img[data-probe="img-data"]')?.naturalWidth > 0,
            cross: document.querySelector('img[data-probe="img-cross"]')?.naturalWidth > 0,
        }));
        expect(imgStates).toEqual({ self: true, data: true, cross: false });

        const report = await openPanel('report');
        await expect.poll(() => getReportedViolations(report)).toEqual({
            "'self'": ['frame-src', 'media-src', 'manifest-src', 'object-src'],
            "'unsafe-inline'": ['script-src'],
            'data:': ['media-src'],
            'https://*.google.com': ['script-src', 'img-src', 'media-src'],
            'https://*.googleapis.com': ['style-src'],
            'https://example.com': ['frame-src'],
        });
    });
});

test.describe('Report Panel: Allowing, Denying, Mutex, & Sandbox Controls', () => {
    test('checking violation checkboxes allows all blocked probes on reload', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        const report = await openPanel('report');
        await expect(report.locator('table#sources input.violation')).toHaveCount(6);

        // Check every reported violation checkbox in #sources (plus 'self' in frame-src
        // and manifest-src because adding an explicit directive overrides default-src 'self' fallback)
        await getSourceCheckbox(report, 'https://*.google.com', 'script-src').check();
        await getSourceCheckbox(report, 'https://*.google.com', 'media-src').check();
        await getSourceCheckbox(report, 'data:', 'media-src').check();
        await getSourceCheckbox(report, 'https://*.github.com', 'connect-src').check();
        await getSourceCheckbox(report, "'self'", 'frame-src').check();
        await getSourceCheckbox(report, 'https://example.com', 'frame-src').check();
        await getSourceCheckbox(report, "'self'", 'manifest-src').check();
        await getSourceCheckbox(report, 'https://example.com', 'manifest-src').check();

        // Use the Report panel's Reload button to reload the active testbench tab
        await Promise.all([
            testbench.waitForNavigation(),
            report.locator('button#reload').click(),
        ]);

        const badges = await getOnloadBadges(testbench);
        for (const [probe, status] of Object.entries(badges)) {
            expect(status, `probe ${probe} should be Allowed`).toBe('Allowed');
        }
    });

    test('unchecking allowed sources or checking \'none\' denies previously allowed probes and enforces \'none\' mutex', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        const report = await openPanel('report');

        // Verify 'none'-leader mutex: checking 'none' in img-src clears 'self', data:, blob:, https:
        const imgNone = getSourceCheckbox(report, "'none'", 'img-src');
        const imgSelf = getSourceCheckbox(report, "'self'", 'img-src');
        const imgHttps = getSourceCheckbox(report, 'https:', 'img-src');

        await expect(await imgSelf.locator()).toBeChecked();
        await expect(await imgHttps.locator()).toBeChecked();

        await imgNone.check();
        await expect(await imgNone.locator()).toBeChecked();
        await expect(await imgSelf.locator()).not.toBeChecked();
        await expect(await imgHttps.locator()).not.toBeChecked();

        // Checking 'self' in img-src automatically unchecks 'none'
        await imgSelf.check();
        await expect(await imgNone.locator()).not.toBeChecked();
        await expect(await imgSelf.locator()).toBeChecked();

        // In First Party mode, 'wasm-unsafe-eval' and 'unsafe-hashes' are unchecked and unviolated
        // (so their .advanced rows are hidden), whereas 'unsafe-eval' is checked (so its row is visible).
        const evalRow = report.locator('table#sources tbody tr').filter({
            has: report.locator('th[title="\'unsafe-eval\'"]'),
        });
        const wasmRow = report.locator('table#sources tbody tr').filter({
            has: report.locator('th[title="\'wasm-unsafe-eval\'"]'),
        });
        const hashesRow = report.locator('table#sources tbody tr').filter({
            has: report.locator('th[title="\'unsafe-hashes\'"]'),
        });
        await expect(evalRow).toBeVisible();
        await expect(wasmRow).not.toBeVisible();
        await expect(hashesRow).not.toBeVisible();

        // Also deny eval(), inline styles, cross-origin fonts, and same-origin fetch
        await getSourceCheckbox(report, "'unsafe-eval'", 'script-src').uncheck();
        await getSourceCheckbox(report, "'unsafe-inline'", 'style-src').uncheck();
        await getSourceCheckbox(report, 'https:', 'font-src').uncheck();
        await getSourceCheckbox(report, "'none'", 'connect-src').check();

        // Unchecking 'unsafe-eval' keeps its row visible during the current edit session (no layout jump)
        await expect(evalRow).toBeVisible();

        await testbench.reload();

        const badges = await getOnloadBadges(testbench);
        expect(badges['eval']).toBe('Blocked');
        expect(badges['inline-style']).toBe('Blocked');
        expect(badges['img-self']).toBe('Allowed');
        expect(badges['img-cross']).toBe('Blocked');
        expect(badges['img-data']).toBe('Blocked');
        expect(badges['font-cross']).toBe('Blocked');
        expect(badges['fetch-self']).toBe('Blocked');

        // After reload, the eval() violation automatically reveals the 'unsafe-eval' row (and 'wasm-unsafe-eval' row)
        await expect(evalRow).toBeVisible();
        await expect(wasmRow).toBeVisible();
        await expect(hashesRow).not.toBeVisible();
    });

    test('toggling sandbox in Report panel enforces sandbox flags and seeds first-party fallback when disabled', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 3); // bare sandbox (default-src is empty)
        await testbench.reload();

        const report = await openPanel('report');
        await expect(report.locator('input#sandbox-enabled')).toBeChecked();

        // Unchecking #sandbox-enabled when default-src is empty triggers fallbackToFirstParty()
        await report.locator('input#sandbox-enabled').uncheck();
        await expect(await getSourceCheckbox(report, "'self'", 'default-src').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, "'unsafe-inline'", 'script-src').locator()).toBeChecked();

        // Re-enable sandbox with allow-scripts only
        await report.locator('input#sandbox-enabled').check();
        await waitForPanelIdle(report);
        await report.locator('input#allow-scripts').check();
        await waitForPanelIdle(report);
        await testbench.reload();

        expect(await testbench.evaluate(() => window.origin)).toBe('null');
        await expect(testbench.locator('#badge-inline-auth')).toHaveText('Allowed');

        // Reset button clears the host's rules
        await report.locator('button#reset').click();
        await expect(report.locator('button#reset')).toBeDisabled();
    });
});
