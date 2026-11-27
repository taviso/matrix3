import {
    test,
    expect,
    setDefaultPolicy,
    waitForPanelIdle,
    getOnloadBadges,
    getReportedViolations,
    getSourceCheckbox,
} from './fixtures.js';

test.describe('Web Workers & Service Workers', () => {
    test('Dedicated Workers (URL, blob:, data:, 3-hop chain) and SharedWorker blocking & unblocking', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        // Under firstparty (worker-src 'none'), all worker types are blocked
        await testbench.locator('#worker-url-btn').click();
        await expect(testbench.locator('#badge-worker')).toHaveText('Blocked');

        await testbench.locator('#worker-blob-btn').click();
        await expect(testbench.locator('#badge-worker')).toHaveText('Blocked');

        await testbench.locator('#worker-data-btn').click();
        await expect(testbench.locator('#badge-worker')).toHaveText('Blocked');

        await testbench.locator('#worker-shared-btn').click();
        await expect(testbench.locator('#badge-shared-worker')).toHaveText('Blocked');

        // Verify worker-src violations ('self', blob:, data:) appear in Report panel
        const report = await openPanel('report');
        await expect(await getSourceCheckbox(report, "'self'", 'worker-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'blob:', 'worker-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'data:', 'worker-src').locator()).toHaveClass(/violation/);

        // Allow 'self', blob:, data: in worker-src, plus 'self', blob:, data: and *.jsdelivr.net in script-src & connect-src
        await getSourceCheckbox(report, "'self'", 'worker-src').check();
        await getSourceCheckbox(report, 'blob:', 'worker-src').check();
        await getSourceCheckbox(report, 'data:', 'worker-src').check();
        await getSourceCheckbox(report, 'blob:', 'script-src').check();
        await getSourceCheckbox(report, 'data:', 'script-src').check();

        // Trigger one worker import so *.jsdelivr.net appears or add it via reload
        await testbench.reload();
        await testbench.locator('#worker-url-btn').click();
        await expect(testbench.locator('#badge-worker')).toHaveText('Blocked');

        // Now *.jsdelivr.net violation is reported under script-src; allow it in script-src & connect-src
        await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'script-src').check();
        await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'connect-src').check();
        await testbench.reload();

        // Verify all 4 Dedicated Worker modes succeed!
        await testbench.locator('#worker-url-btn').click();
        await expect(testbench.locator('#badge-worker')).toHaveText('Allowed');

        await testbench.locator('#worker-blob-btn').click();
        await expect(testbench.locator('#badge-worker')).toHaveText('Allowed');

        await testbench.locator('#worker-data-btn').click();
        await expect(testbench.locator('#badge-worker')).toHaveText('Allowed');

        await testbench.locator('#worker-chain-btn').click();
        await expect(testbench.locator('#badge-worker')).toHaveText('Allowed');

        // Verify SharedWorker connect, fetch(jsdelivr), and close all succeed!
        await testbench.locator('#worker-shared-btn').click();
        await expect(testbench.locator('#badge-shared-worker')).toContainText('Conn #1');

        await testbench.locator('#worker-shared-fetch-btn').click();
        await expect(testbench.locator('#badge-worker')).toHaveText('Allowed');

        await testbench.locator('#worker-shared-close-btn').click();
        await expect(testbench.locator('#badge-shared-worker')).toHaveText('Terminated');
    });

    // Disabled until Chromium ships DispatchWorkerCSPViolationEventForModuleGraphFetching (crbug.com/40612680).
    test.skip('module blob: worker static import reports worker-src violation', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        const report = await openPanel('report');
        await getSourceCheckbox(report, "'self'", 'worker-src').check();
        await getSourceCheckbox(report, 'blob:', 'worker-src').check();
        await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'script-src').check();
        await Promise.all([
            testbench.waitForNavigation(),
            report.locator('button#reload').click(),
        ]);

        await testbench.locator('#worker-module-blob-btn').click();
        await expect(testbench.locator('#badge-worker')).toHaveText('Blocked');
        await expect(await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'worker-src').locator()).toHaveClass(/violation/, { timeout: 3000 });

        await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'worker-src').check();
        await Promise.all([
            testbench.waitForNavigation(),
            report.locator('button#reload').click(),
        ]);
        await testbench.locator('#worker-module-blob-btn').click();
        await expect(testbench.locator('#badge-worker')).toHaveText('Allowed');
    });

    test('Service Worker registration, detection, tabless violation attribution, and 🔧 unregistration', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        // Blocked when worker-src is 'none'
        await testbench.locator('#sw-reg-btn').click();
        await expect(testbench.locator('#badge-sw')).toHaveText('Blocked');

        // Allow worker-src 'self' and reload
        const report = await openPanel('report');
        await getSourceCheckbox(report, "'self'", 'worker-src').check();
        await testbench.reload();

        // Register /sw.js and reload so it controls the page
        await testbench.locator('#sw-reg-btn').click();
        await expect(testbench.locator('#badge-sw')).toHaveText(/^(Registered|Controlling Page)$/);
        await testbench.reload();
        await expect(testbench.locator('#badge-sw')).toHaveText('Controlling Page');

        // Tabless WebSocket violation inside Service Worker (tabId === -1) is attributed to the tab
        await testbench.locator('#ws-sw-btn').click();
        await expect(testbench.locator('#badge-ws')).toContainText('Blocked');
        await expect(await getSourceCheckbox(report, 'wss://*.websocket.org', 'connect-src').locator()).toHaveClass(/violation/);

        // Verify page JS cannot spoof a CSP violation report via new WebSocket(), fetch(), or sendBeacon()
        // to either internal report-uri endpoint (wss://_matrix3.internal/csp-report or chrome-extension://.../csp-report).
        const warReportUrl = await serviceWorker.evaluate(() => chrome.runtime.getURL('csp-report'));
        await testbench.evaluate(async (warUrl) => {
            const fakeBody = JSON.stringify({
                'csp-report': {
                    'document-uri': location.href,
                    'effective-directive': 'script-src-elem',
                    'blocked-uri': 'https://spoofed.example.net/evil.js',
                },
            });
            try {
                const ws = new WebSocket('wss://_matrix3.internal/csp-report');
                await new Promise((r) => {
                    ws.onerror = ws.onclose = r;
                });
            } catch {}
            try {
                await fetch('wss://_matrix3.internal/csp-report', { method: 'POST', body: fakeBody });
            } catch {}
            try {
                await fetch(warUrl, { method: 'POST', body: fakeBody });
            } catch {}
            try {
                navigator.sendBeacon(warUrl, fakeBody);
            } catch {}
        }, warReportUrl);
        await expect(report.locator('table#sources tbody tr th[title*="spoofed"]')).toHaveCount(0);

        // The 🔧 (button.unregistersw) button on the 127.0.0.1 origin tab should now be enabled
        const swBtn = report.locator('div#frames button[data-value="127.0.0.1"] button.unregistersw');
        await expect(swBtn).toBeEnabled();

        // Opening a second tab to the same origin and closing it must not remove the
        // tracked Service Worker while the first tab is still open.
        const secondTab = await testbench.context().newPage();
        await secondTab.goto(testbench.url());
        await expect(secondTab.locator('#badge-sw')).toHaveText('Controlling Page');
        await secondTab.close();
        await testbench.bringToFront();
        const workersAfterClose = await report.evaluate(() =>
            chrome.runtime.sendMessage({ command: 'reqworkers' })
        );
        expect(workersAfterClose).toContain('127.0.0.1');
        await expect(swBtn).toBeEnabled();

        // Clicking 🔧 unregisters the Service Worker and disables the button
        await swBtn.click();
        await expect(swBtn).toBeDisabled();

        await testbench.reload();
        await expect(testbench.locator('#badge-sw')).toHaveText('Not Registered');
    });

    test('navigating a second same-origin tab away preserves the tracked Service Worker, and reloading the last tab after unregistration clears it', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        const report = await openPanel('report');
        await getSourceCheckbox(report, "'self'", 'worker-src').check();
        await testbench.reload();

        try {
            // Register /sw.js and reload so it controls the page.
            await testbench.locator('#sw-reg-btn').click();
            await expect(testbench.locator('#badge-sw')).toHaveText(/^(Registered|Controlling Page)$/);
            await testbench.reload();
            await expect(testbench.locator('#badge-sw')).toHaveText('Controlling Page');

            const reqWorkers = (page) => page.evaluate(() => chrome.runtime.sendMessage({ command: 'reqworkers' }));
            await expect.poll(() => reqWorkers(report)).toContain('127.0.0.1');

            // A second tab on the same origin, also controlled by the Service Worker.
            const secondTab = await testbench.context().newPage();
            await secondTab.goto(testbench.url());
            await expect(secondTab.locator('#badge-sw')).toHaveText('Controlling Page');

            // Let the second tab's post-navigation SW soft-update check (kUpdateDelay = 1s)
            // finish, so it cannot re-add the origin after the navigation below and mask the result.
            await secondTab.waitForTimeout(2000);

            // Navigate the second tab to a different origin. onBeforeNavigate -> resetViolations(tab2)
            // must not forget the Service Worker while the first tab is still controlled by it.
            await secondTab.goto('http://localhost:8123/reset');
            await secondTab.waitForTimeout(1500);

            expect(await reqWorkers(report)).toContain('127.0.0.1');

            // The unregister button for the first tab's origin must still be enabled in a freshly opened panel.
            await testbench.bringToFront();
            const freshReport = await openPanel('report');
            await expect(freshReport.locator('div#frames button[data-value="127.0.0.1"] button.unregistersw')).toBeEnabled();

            await secondTab.close();

            // Inverse check: once the SW unregisters itself and the last remaining tab
            // on that origin reloads, resetViolations must clear the origin from #workers
            // so 🔧 does not stay stuck enabled.
            await testbench.evaluate(async () => {
                for (const reg of await navigator.serviceWorker.getRegistrations()) await reg.unregister();
            });
            await testbench.reload();
            await expect(testbench.locator('#badge-sw')).toHaveText('Not Registered');
            await expect.poll(() => reqWorkers(report)).not.toContain('127.0.0.1');
            await expect(freshReport.locator('div#frames button[data-value="127.0.0.1"] button.unregistersw')).toBeDisabled();
        } finally {
            // Clean up: unregister the SW and drop it from the tracker so later tests start clean.
            await testbench.evaluate(async () => {
                for (const reg of await navigator.serviceWorker.getRegistrations()) await reg.unregister();
            }).catch(() => {});
            await report.evaluate(() =>
                chrome.runtime.sendMessage({ command: 'delworker', data: { domain: '127.0.0.1' } })
            ).catch(() => {});
        }
    });

    test('7. installed service worker wakes back up cleanly after idle stop', async ({
        context,
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 4);
        const cdp = await context.newCDPSession(testbench);
        await cdp.send('ServiceWorker.enable');
        await cdp.send('ServiceWorker.stopAllWorkers');

        // Navigate after stopping the installed MV3 service worker; waking it from
        // InstalledScriptsManager must succeed and record new violations.
        await testbench.goto('http://127.0.0.1:8123/reset');
        const report = await openPanel('report');
        await expect(await getSourceCheckbox(report, "'unsafe-inline'", 'script-src').locator()).toHaveClass(
            /\bviolation\b/
        );
    });
});
