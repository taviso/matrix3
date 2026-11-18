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

test.describe('Interactive Testbench Probes: Workers, Contexts, Schemes, & Service Worker', () => {
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

    test('<object> navigation CSP injection, 302 redirect resolution, srcdoc attribution, and special schemes', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        // 1. <object data="/frame.html?fetch=1"> loads under object-src 'self', and inner fetch is governed by connect-src
        await testbench.locator('#object-btn').click();
        await expect(testbench.locator('#badge-special')).toHaveText('Object Loaded');

        // 2. Sandboxed srcdoc iframe attributes opaque-origin fetch(https://untrusted.example.com/) via documentId
        await testbench.locator('#srcdoc-btn').click();
        await expect(testbench.locator('#badge-special')).toHaveText('Fetch Blocked (Check Report)');

        // 3. 302 Redirect (/redirect -> https://cdn.jsdelivr.net/npm/d3/+esm) resolves post-redirect target
        await testbench.locator('#redirect-btn').click();
        await expect(testbench.locator('#badge-special')).toHaveText('Blocked');

        // 4. Special schemes: frame:data (empty blocked-uri "" -> data:), frame:blob (blob:), ws:wss (wss://*.websocket.org), and #long-host-btn
        await testbench.locator('#scheme-select').selectOption('frame:data');
        await testbench.locator('#weird-schemes-btn').click();

        await testbench.locator('#scheme-select').selectOption('frame:blob');
        await testbench.locator('#weird-schemes-btn').click();

        await testbench.locator('#long-host-btn').click();
        await expect(testbench.locator('#badge-special')).toHaveText('Dispatched');

        await testbench.locator('#ws-page-btn').click();
        await expect(testbench.locator('#badge-ws')).toContainText('Blocked');

        const report = await openPanel('report');
        await expect(await getSourceCheckbox(report, 'https://*.example.com', 'connect-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'script-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'data:', 'frame-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'blob:', 'frame-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'wss://*.websocket.org', 'connect-src').locator()).toHaveClass(/violation/);

        // Allow https://*.jsdelivr.net in script-src and verify /redirect script succeeds on reload
        await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'script-src').check();
        await testbench.reload();
        await testbench.locator('#redirect-btn').click();
        await expect(testbench.locator('#badge-special')).toHaveText('Allowed');
    });

    test('caps per-tab domains at 128, per-directive blocked sources at 1024, folds overflow into scheme, and rejects fakeprotocol:// spam', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        // 1. Trigger fakeprotocol:// violations (which have origin "null" in WHATWG URL) and a real
        //    https:// violation in the browser, verifying fakeprotocol:// is rejected end-to-end.
        await testbench.evaluate(() => {
            for (let i = 0; i < 10; i++) {
                const img = new Image();
                img.src = `fakeprotocol${i}://evil.example/x.png`;
            }
            fetch('https://real-violation.invalid/').catch(() => {});
        });

        const panel = await openPanel('options');
        await expect
            .poll(
                async () => {
                    return await panel.evaluate(async () => {
                        const [tab] = await chrome.tabs.query({ active: true });
                        const policy = await chrome.runtime.sendMessage({
                            command: 'reqpolicy',
                            data: { id: tab.id, domain: '127.0.0.1' },
                        });
                        const connectSrc = policy?.['connect-src'] ?? [];
                        const imgSrc = policy?.['img-src'] ?? [];
                        return {
                            hasRealViolation: connectSrc.includes('https://real-violation.invalid'),
                            hasFakeProtocol: [...connectSrc, ...imgSrc].some((s) => s.startsWith('fakeprotocol')),
                        };
                    });
                },
                { timeout: 10000 }
            )
            .toEqual({
                hasRealViolation: true,
                hasFakeProtocol: false,
            });

        // 2. Verify kMaxSources (1024) + scheme folding and kMaxDomains (128) on ViolationTracker.
        const trackerCaps = await panel.evaluate(async () => {
            const { default: ViolationTracker } = await import('/include/tracker.js');
            const vt = new ViolationTracker();
            await vt.resetViolations(9999);
            await vt.resetServerPolicy(9999);

            // 1,100 distinct blocked https:// origins on frame0.com: first 1,024 are stored
            // individually; a repeat report for an already-stored origin at 1,024 must NOT fold
            // into "https:", whereas the 1,025th distinct origin folds into "https:".
            await vt.addDocument(9999, 'doc-0', 'https://frame0.com/');
            for (let i = 0; i < 1024; i++) {
                await vt.addTabViolation(9999, {
                    report: { 'document-uri': 'https://frame0.com/' },
                    directive: 'connect-src',
                    blocked: new URL(`https://s${i}.invalid/`),
                    documentId: 'doc-0',
                });
            }
            const repeatAtCapAdded = await vt.addTabViolation(9999, {
                report: { 'document-uri': 'https://frame0.com/' },
                directive: 'connect-src',
                blocked: new URL('https://s0.invalid/'),
                documentId: 'doc-0',
            });
            const dirsAtCap = await vt.getDirectives(9999, 'frame0.com');
            const countBeforeOverflow = dirsAtCap['connect-src']?.length ?? 0;
            const hasHttpsBeforeOverflow = dirsAtCap['connect-src']?.includes('https:') ?? false;
            for (let i = 1024; i < 1100; i++) {
                await vt.addTabViolation(9999, {
                    report: { 'document-uri': 'https://frame0.com/' },
                    directive: 'connect-src',
                    blocked: new URL(`https://s${i}.invalid/`),
                    documentId: 'doc-0',
                });
            }
            // Non-special schemes after reaching kMaxSources are still rejected.
            const fakeAdded = await vt.addTabViolation(9999, {
                report: { 'document-uri': 'https://frame0.com/' },
                directive: 'connect-src',
                blocked: new URL('fakeprotocol://evil.example/'),
                documentId: 'doc-0',
            });

            // 140 distinct frame domains: first 128 are tracked in policy and server, overflow is dropped,
            // while existing domains within the first 128 still accept new violations.
            for (let i = 0; i < 140; i++) {
                const docId = `doc-${i}`;
                const url = `https://frame${i}.com/`;
                await vt.addDocument(9999, docId, url);
                await vt.addServerPolicy(9999, url, "default-src 'self'");
                await vt.addTabViolation(9999, {
                    report: { 'document-uri': url },
                    directive: 'img-src',
                    blocked: new URL('https://cdn.example.net/a.png'),
                    documentId: docId,
                });
            }
            const addedToFirst = await vt.addTabViolation(9999, {
                report: { 'document-uri': 'https://frame0.com/' },
                directive: 'img-src',
                blocked: new URL('https://other.org/b.png'),
                documentId: 'doc-0',
            });
            const firstDirs = await vt.getDirectives(9999, 'frame0.com');
            const lastAllowedDirs = await vt.getDirectives(9999, 'frame127.com');
            const overflowDirs = await vt.getDirectives(9999, 'frame128.com');
            const overflowServer = await vt.getServerPolicy(9999, 'frame128.com');
            await vt.resetTab(9999);

            // 3. Verify Object.prototype property names ("__proto__", "constructor", "toString")
            //    as hostnames do not pollute Object.prototype or throw in addServerPolicy/addTabViolation.
            for (const protoHost of ['__proto__', 'constructor', 'toString']) {
                const url = `http://${protoHost}/`;
                await vt.addDocument(9998, `doc-${protoHost}`, url);
                await vt.addServerPolicy(9998, url, "default-src 'self'");
                await vt.addTabViolation(9998, {
                    report: { 'document-uri': url },
                    directive: 'img-src',
                    blocked: new URL('https://cdn.example.net/a.png'),
                    documentId: `doc-${protoHost}`,
                });
            }
            const protoDirs = await vt.getDirectives(9998, '__proto__');
            const ctorServer = await vt.getServerPolicy(9998, 'constructor');
            const pollutedProto = 'img-src' in Object.prototype || 'img-src' in Object;
            await vt.resetTab(9998);

            // 4. Verify addServiceWorker acts as a 1,024-entry FIFO circular buffer.
            for (let i = 0; i < 1025; i++) {
                await vt.addServiceWorker(`https://sw${i}.com/sw.js`);
            }
            const swList = await vt.getServiceWorkers();
            const swCount = swList.length;
            const swOldestEvicted = !swList.includes('sw0.com');
            const swNewestKept = swList.includes('sw1024.com');
            for (let i = 1; i < 1025; i++) {
                await vt.delServiceWorker(`sw${i}.com`);
            }

            return {
                repeatAtCapAdded,
                countBeforeOverflow,
                hasHttpsBeforeOverflow,
                connectCount: firstDirs['connect-src']?.length ?? 0,
                hasHttpsScheme: firstDirs['connect-src']?.includes('https:') ?? false,
                fakeAdded,
                addedToFirst,
                firstImgCount: firstDirs['img-src']?.length ?? 0,
                lastAllowedCount: lastAllowedDirs['img-src']?.length ?? 0,
                overflowCount: Object.keys(overflowDirs).length,
                overflowServerCount: overflowServer.length,
                protoImgSrc: protoDirs['img-src'] ?? [],
                ctorServer,
                pollutedProto,
                swCount,
                swOldestEvicted,
                swNewestKept,
            };
        });
        expect(trackerCaps).toEqual({
            repeatAtCapAdded: false,
            countBeforeOverflow: 1024,
            hasHttpsBeforeOverflow: false,
            connectCount: 1025,
            hasHttpsScheme: true,
            fakeAdded: false,
            addedToFirst: true,
            firstImgCount: 2,
            lastAllowedCount: 1,
            overflowCount: 0,
            overflowServerCount: 0,
            protoImgSrc: ['https://*.example.net'],
            ctorServer: ["default-src 'self'"],
            pollutedProto: false,
            swCount: 1024,
            swOldestEvicted: true,
            swNewestKept: true,
        });
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

    test('Testbench Policy Builder and Server Suggested Policy (#accept, #merge, dirty state, passthrough)', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        // Use the Testbench Policy Builder UI to construct a server CSP
        await testbench.locator('#builder-directive').selectOption('script-src');
        await testbench.locator('#builder-source').selectOption("'nonce-test-nonce'");
        await testbench.locator('#builder-append-btn').click();

        await testbench.locator('#builder-source').selectOption("'wasm-unsafe-eval'");
        await testbench.locator('#builder-append-btn').click();

        await testbench.locator('#builder-source').selectOption('__other__');
        await testbench.locator('#builder-custom').fill('https://cdn.jsdelivr.net/npm/d3/');
        await testbench.locator('#builder-append-btn').click();

        await testbench.locator('#builder-directive').selectOption('upgrade-insecure-requests');
        await testbench.locator('#builder-append-btn').click();

        await testbench.locator('#builder-directive').selectOption('report-uri');
        await testbench.locator('#builder-append-btn').click();

        await testbench.locator('form.csp-form button[type="submit"]').click();

        const report = await openPanel('report');
        const details = report.locator('div#serverpolicy details');
        await expect(details).toBeVisible();
        await details.locator('summary').click();

        // Passthrough textarea shows upgrade-insecure-requests but strips report-uri
        await expect(report.locator('textarea#servercsp')).toHaveText('upgrade-insecure-requests;');

        // Path suffix on https://cdn.jsdelivr.net/npm/d3/ was stripped to https://cdn.jsdelivr.net
        await expect(await getSourceCheckbox(report, 'https://cdn.jsdelivr.net', 'script-src', 'table#serversources').locator()).toBeChecked();

        // Merge adds server sources to existing First-Party selections (keeping style-src https:)
        await report.locator('button#merge').click();
        await expect(await getSourceCheckbox(report, 'https://cdn.jsdelivr.net', 'script-src').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, 'https:', 'style-src').locator()).toBeChecked();

        // Accept replaces selections with only the server policy (translating nonce -> 'unsafe-inline' + 'self')
        await report.locator('button#accept').click();
        await expect(await getSourceCheckbox(report, "'unsafe-inline'", 'script-src').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, "'wasm-unsafe-eval'", 'script-src').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, "'self'", 'script-src').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, 'https://cdn.jsdelivr.net', 'script-src').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, 'https:', 'style-src').locator()).not.toBeChecked();

        // Unchecking an advanced source imported via Accept ('wasm-unsafe-eval') must not make its row vanish mid-edit
        await getSourceCheckbox(report, "'wasm-unsafe-eval'", 'script-src').uncheck();
        await expect(report.locator('table#sources tbody th[title="\'wasm-unsafe-eval\'"]')).toBeVisible();
    });

    test('Additive CSP (operation: "append"): intersection with multiple & comma-combined server headers and nonce preservation', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        // 1. Server tightens matrix³ (Permissive mode 0 + 3 server CSP headers including a comma-combined header):
        //    - Header 1 allows script-src 'self' 'nonce-test-nonce' https://example.com
        //    - Header 2 (comma-combined) sets style-src 'self' 'unsafe-inline', img-src 'self' data:
        //    - Header 3 restricts script-src 'self' 'nonce-test-nonce'; connect-src 'none'; form-action 'self'; report-uri /report
        await setDefaultPolicy(serviceWorker, 0);
        const multiHeaderCsp = [
            "script-src 'self' 'nonce-test-nonce' https://example.com",
            "style-src 'self' 'unsafe-inline', img-src 'self' data:",
            "script-src 'self' 'nonce-test-nonce'; connect-src 'none'; form-action 'self'; report-uri /report",
        ].join('\n');

        await testbench.locator('#csp').fill(multiHeaderCsp);
        await testbench.locator('form.csp-form button[type="submit"]').click();

        const badges = await getOnloadBadges(testbench);
        // Allowed by intersection of all 3 server headers + matrix³ permissive:
        expect(badges['inline-auth']).toBe('Allowed'); // matches 'nonce-test-nonce'
        expect(badges['inline-style']).toBe('Allowed');
        expect(badges['img-self']).toBe('Allowed');
        expect(badges['img-data']).toBe('Allowed');

        // Blocked by intersection (Header 3 blocks ext-script, inline-plain, eval, wasm, fetch-self, fetch; Header 2 blocks ext-style, img-cross):
        expect(badges['inline-plain']).toBe('Blocked'); // lacks nonce="test-nonce"
        expect(badges['ext-script']).toBe('Blocked'); // allowed in Header 1 & matrix³, blocked by Header 3
        expect(badges['eval']).toBe('Blocked');
        expect(badges['wasm']).toBe('Blocked');
        expect(badges['ext-style']).toBe('Blocked');
        expect(badges['img-cross']).toBe('Blocked');
        expect(badges['fetch-self']).toBe('Blocked');
        expect(badges['fetch']).toBe('Blocked');

        const report = await openPanel('report');
        // Server-only CSP violations (reported to /report) are filtered by kReportUrls and must not pollute matrix³'s violation table
        expect(await getReportedViolations(report)).toEqual({});

        // Verify all 4 parsed server policies (from 3 headers, one comma-combined) populate #serversources and #servercsp
        const details = report.locator('div#serverpolicy details');
        await expect(details).toBeVisible();
        await details.locator('summary').click();

        await expect(report.locator('textarea#servercsp')).toHaveText("form-action 'self';");
        await expect(await getSourceCheckbox(report, "'self'", 'script-src', 'table#serversources').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, "'nonce-test-nonce'", 'script-src', 'table#serversources').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, 'https://example.com', 'script-src', 'table#serversources').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, "'self'", 'style-src', 'table#serversources').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, 'data:', 'img-src', 'table#serversources').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, "'none'", 'connect-src', 'table#serversources').locator()).toBeChecked();

        // 2. Under Strict mode (4), clicking Accept (#accept) overrides strict.json via the host (allow, append) rule pair,
        //    translating 'nonce-test-nonce' -> 'unsafe-inline' + 'self' in matrix³'s appended header while the server's
        //    header still enforces 'nonce-test-nonce' (allowing inline-auth while blocking inline-plain).
        await setDefaultPolicy(serviceWorker, 4);
        await report.locator('button#accept').click();
        await waitForPanelIdle(report);
        await testbench.reload();

        const badgesAfterAccept = await getOnloadBadges(testbench);
        expect(badgesAfterAccept['inline-auth']).toBe('Allowed');
        expect(badgesAfterAccept['inline-plain']).toBe('Blocked');
        expect(badgesAfterAccept['ext-script']).toBe('Blocked');
        expect(badgesAfterAccept['inline-style']).toBe('Allowed');
        expect(badgesAfterAccept['img-self']).toBe('Allowed');
        expect(badgesAfterAccept['img-data']).toBe('Allowed');
    });

    test('Malformed, duplicate, valueless, path-suffixed, and unusual Server CSP headers are handled safely', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);

        // Construct an unusual/malformed multi-header + comma-separated server CSP:
        // - Empty/whitespace segments and stray semicolons/commas
        // - Duplicate directive in same policy: font-src 'self'; font-src https://evil.example.com (second must be ignored per W3C CSP3)
        // - Valueless fetch directive: object-src; (equivalent to object-src 'none')
        // - Sub-directives: script-src-elem https://cdn.jsdelivr.net/npm/d3/+esm; style-src-attr 'unsafe-hashes'
        // - Path-suffixed host with port, wildcard subdomain, and wildcard port: connect-src https://api.example.com:8443/v1/users?active=1 https://*.example.com/assets/ https://ws.example.com:*/socket sub.example.com/dir/
        // - Nonsense schemes, malformed ports, invalid wildcards, credentials, relative paths, and weird Unicode/RTL/homograph codepoints
        // - Prototype-keys as unknown directives: __proto__ foo; constructor bar; toString baz
        // - Sandbox directive from server: sandbox allow-scripts allow-same-origin
        const rejectedSources = [
            // Nonsense / disallowed schemes
            'javascript://foo.com/%0aalert(1)',
            'data://foo.com/bar',
            'ftp://files.example.com/pub',
            'custom+scheme://foo.com/bar',
            'http:///empty-host.com/bar',
            '://missing-scheme.com/bar',
            // Malformed ports (named parameter syntax, empty, alphanumeric, double colon)
            'http://foo.com:wtf',
            'http://foo.com:wtf/bar',
            'https://foo.com:/bar',
            'https://foo.com:80a/bar',
            'https://foo.com:*80/bar',
            'https://foo.com:80:80/bar',
            'foo.com:wtf/bar',
            // Invalid wildcard placements & relative path tricks
            'https://*.*.example.com/path',
            'https://**.example.com/path',
            'https://sub.*.example.com/path',
            'https://*example.com/path',
            '*.*.example.com/path',
            '/relative.example.com/bar',
            '//schemeless.example.com/bar',
            // Credentials, query/hash without slash, IPv6 literal, bogus keywords
            'https://user:pass@example.com/path',
            'https://example.com?query=1',
            'https://example.com#hash',
            'http://[::1]/path',
            "'bogus-kw'",
            "'SELF'",
            '???',
            // RTL overrides (U+202E), zero-width space (U+200B), Cyrillic homograph (U+0430), C1/DEL control chars (U+0085, U+007F)
            'https://\u202eexample.com/path',
            'https://ex\u202eample.com',
            '\u202esub.example.com/path',
            'https://exam\u200bple.com/path',
            'https://\u0430pple.com/path',
            'https://example.com\u0085/path',
            'https://ex\u007fample.com/path',
        ];
        const weirdCsp = [
            " , ;;; font-src 'self'; font-src https://evil.example.com; object-src; ;;; ",
            "script-src 'self' 'nonce-test-nonce'; script-src-elem https://cdn.jsdelivr.net/npm/d3/+esm; style-src-attr 'unsafe-hashes'",
            `connect-src https://api.example.com:8443/v1/users?active=1 https://*.example.com/assets/ https://ws.example.com:*/socket sub.example.com/dir/; media-src 'self' ${rejectedSources.join(' ')}`,
            "__proto__ foo; constructor bar; toString baz; sandbox allow-scripts allow-same-origin; report-to endpoint-1",
        ].join('\n');

        await testbench.locator('#csp').fill(weirdCsp);
        await testbench.locator('form.csp-form button[type="submit"]').click();

        const report = await openPanel('report');
        const details = report.locator('div#serverpolicy details');
        await expect(details).toBeVisible();
        await details.locator('summary').click();

        // 1. First font-src ('self') is honored; duplicate font-src (https://evil.example.com) is ignored
        await expect(await getSourceCheckbox(report, "'self'", 'font-src', 'table#serversources').locator()).toBeChecked();
        await expect(report.locator('table#serversources tbody tr th[title="https://evil.example.com"]')).toHaveCount(0);

        // 2. Valueless object-src; is treated as 'none' (and reveals advanced column)
        await expect(await getSourceCheckbox(report, "'none'", 'object-src', 'table#serversources').locator()).toBeChecked();

        // 3. Sub-directives collapse into script-src and style-src, and path suffixes are stripped
        await expect(await getSourceCheckbox(report, 'https://cdn.jsdelivr.net', 'script-src', 'table#serversources').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, "'unsafe-hashes'", 'style-src', 'table#serversources').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, 'https://api.example.com:8443', 'connect-src', 'table#serversources').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, 'https://*.example.com', 'connect-src', 'table#serversources').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, 'https://ws.example.com:*', 'connect-src', 'table#serversources').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, 'sub.example.com', 'connect-src', 'table#serversources').locator()).toBeChecked();

        // 4. Valid media-src 'self' survives alongside all hostile/malformed/RTL/homograph tokens,
        //    and the entire #serversources table contains ONLY the expected valid source rows.
        await expect(await getSourceCheckbox(report, "'self'", 'media-src', 'table#serversources').locator()).toBeChecked();
        const serverRowTitles = await report
            .locator('table#serversources tbody tr th')
            .evaluateAll((ths) => ths.map((th) => th.title));
        expect(serverRowTitles).toEqual([
            "'none'",
            "'self'",
            "'unsafe-hashes'",
            'https://*.example.com',
            'https://api.example.com:8443',
            'https://cdn.jsdelivr.net',
            'https://ws.example.com:*',
            'sub.example.com',
            "'nonce-test-nonce'",
        ]);

        // 5. Object.prototype keys (__proto__, constructor, toString) do not throw or pollute Object.prototype,
        //    and report-to is stripped from passthrough
        const serverCspText = await report.locator('textarea#servercsp').textContent();
        expect(serverCspText).toContain('__proto__ foo;');
        expect(serverCspText).toContain('constructor bar;');
        expect(serverCspText).toContain('tostring baz;');
        expect(serverCspText).not.toContain('report-to');

        // 6. Clicking #accept applies the server's sandbox flags (allow-scripts, allow-same-origin) into table#sandbox
        await report.locator('button#accept').click();
        await waitForPanelIdle(report);
        await expect(report.locator('input#sandbox-enabled')).toBeChecked();
        await expect(report.locator('input#allow-scripts')).toBeChecked();
        await expect(report.locator('input#allow-same-origin')).toBeChecked();
        await expect(report.locator('input#allow-forms')).not.toBeChecked();
    });

    test('Cookies and sandbox interaction: pre-existing cookies, document.cookie, subresource fetch/img, form GET/POST, and allow-same-origin restoration', async ({
        context,
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await context.clearCookies();

        // 1. Mode 1 (First Party, no sandbox): set JS and HTTP cookies before enabling sandbox
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.goto('http://127.0.0.1:8123/reset');

        const preSandbox = await testbench.evaluate(async () => {
            document.cookie = 'js_pre=1; Path=/';
            await fetch('/cookie-echo?set=1');
            const echo = await (await fetch('/cookie-echo')).json();
            return {
                origin: window.origin,
                docCookie: document.cookie,
                fetchCookie: echo.cookie,
            };
        });

        expect(preSandbox.origin).toBe('http://127.0.0.1:8123');
        expect(preSandbox.docCookie).toContain('js_pre=1');
        expect(preSandbox.docCookie).toContain('http_default=1');
        expect(preSandbox.docCookie).toContain('http_lax=1');
        expect(preSandbox.docCookie).toContain('http_strict=1');
        expect(preSandbox.docCookie).not.toContain('http_only=1'); // HttpOnly hidden from document.cookie
        for (const c of ['js_pre=1', 'http_default=1', 'http_lax=1', 'http_strict=1', 'http_only=1']) {
            expect(preSandbox.fetchCookie).toContain(c);
        }

        // 2. Switch to Mode 2 (Sandbox + Scripts / sandbox-lite: `sandbox allow-scripts allow-forms`, NO allow-same-origin)
        await setDefaultPolicy(serviceWorker, 2);
        await testbench.reload();

        // Pre-existing cookies are NOT deleted from the browser's cookie jar
        const jarInSandbox = await context.cookies('http://127.0.0.1:8123/');
        expect(jarInSandbox.map((c) => c.name).sort()).toEqual([
            'http_default',
            'http_lax',
            'http_only',
            'http_strict',
            'js_pre',
        ]);

        // Inspect how sandbox-lite (opaque origin "null") interacts with every cookie mechanism
        const inSandboxLite = await testbench.evaluate(async () => {
            let readError = null;
            let writeError = null;
            let storageError = null;

            try {
                void document.cookie;
            } catch (e) {
                readError = e.name;
            }
            try {
                document.cookie = 'js_sandbox=1; Path=/';
            } catch (e) {
                writeError = e.name;
            }
            try {
                void localStorage.length;
            } catch (e) {
                storageError = e.name;
            }

            // (a) Standard same-path fetch('/cookie-echo') without CORS headers fails outright with TypeError
            //     because window.origin is "null" (opaque), making same-host fetch() a cross-origin request!
            let nonCorsFetchFailed = false;
            try {
                await fetch('/cookie-echo?record=1');
            } catch {
                nonCorsFetchFailed = true;
            }

            // (b) Even when the server allows Origin: null (?cors=1), default fetch() (credentials: 'same-origin')
            //     treats /cookie-echo as cross-origin relative to "null" -> no cookies sent, Set-Cookie ignored!
            const sameOriginFetch = await (
                await fetch('/cookie-echo?cors=1&set_from_sub=blocked_in_sandbox')
            ).json();

            // (c) fetch('/cookie-echo?cors=1', { credentials: 'include' }):
            //     Even with credentials: 'include' + CORS, the sandboxed document's SiteForCookies is opaque,
            //     so SameSite=Lax (and default) and SameSite=Strict cookies are withheld.
            const includeFetch = await (
                await fetch('/cookie-echo?cors=1', { credentials: 'include' })
            ).json();

            // (d) Declarative subresource (<img src="/cookie-echo?record=1">):
            //     Also governed by the document's opaque SiteForCookies -> SameSite=Lax/Strict withheld.
            await new Promise((resolve) => {
                const img = new Image();
                img.onload = img.onerror = resolve;
                img.src = `/cookie-echo?record=1&t=${Date.now()}`;
            });
            const afterImg = await (await fetch('/cookie-echo?cors=1')).json();

            return {
                origin: window.origin,
                readError,
                writeError,
                storageError,
                nonCorsFetchFailed,
                lastNavCookie: sameOriginFetch.last_nav_cookie,
                sameOriginFetchCookie: sameOriginFetch.cookie,
                includeFetchCookie: includeFetch.cookie,
                imgSubresourceCookie: afterImg.last_subresource_cookie,
            };
        });

        expect(inSandboxLite.origin).toBe('null');
        // document.cookie (both read and write) and localStorage throw SecurityError in sandbox-lite
        expect(inSandboxLite.readError).toBe('SecurityError');
        expect(inSandboxLite.writeError).toBe('SecurityError');
        expect(inSandboxLite.storageError).toBe('SecurityError');
        expect(inSandboxLite.nonCorsFetchFailed).toBe(true);

        // Subtle HTTP detail: the initial top-level GET / navigation request itself goes out *before* the
        // response's `Content-Security-Policy: sandbox` header is applied, so top-level GET / still sent the cookies:
        for (const c of ['js_pre=1', 'http_default=1', 'http_lax=1', 'http_strict=1', 'http_only=1']) {
            expect(inSandboxLite.lastNavCookie).toContain(c);
        }

        // Once the sandboxed document commits (origin "null"), subresource requests (fetch, credentials: 'include', <img>)
        // cannot send any of the cookies, nor can subresource responses set cookies:
        expect(inSandboxLite.sameOriginFetchCookie).toBe('');
        expect(inSandboxLite.includeFetchCookie).toBe('');
        expect(inSandboxLite.imgSubresourceCookie).toBe('');
        const jarAfterSubSet = await context.cookies('http://127.0.0.1:8123/');
        expect(jarAfterSubSet.map((c) => c.name)).not.toContain('sub_cookie');

        // Form submissions (allowed by `allow-forms` in sandbox-lite):
        // Because the form's initiator origin is opaque ("null"), Chromium treats the navigation as cross-site:
        // - Top-level <form method="POST"> withholds BOTH SameSite=Strict (`http_strict=1`) and explicit SameSite=Lax (`http_lax=1`)!
        //   (Cookies without an explicit SameSite attribute fall under Chromium's 2-minute Lax-allowing-unsafe grace window for top-level POST.)
        await testbench.evaluate(() => {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/cookie-echo';
            document.body.appendChild(form);
            form.submit();
        });
        await testbench.waitForURL('**/cookie-echo');
        const formPostResult = JSON.parse(await testbench.locator('body').innerText());
        expect(formPostResult.method).toBe('POST');
        expect(formPostResult.cookie).not.toContain('http_strict=1');
        expect(formPostResult.cookie).not.toContain('http_lax=1');

        // - Top-level <form method="GET"> from the sandboxed document is a cross-site top-level GET navigation,
        //   so SameSite=Strict (`http_strict=1`) is withheld while SameSite=Lax / default cookies ARE sent!
        await testbench.goto('http://127.0.0.1:8123/');
        await testbench.evaluate(() => {
            const form = document.createElement('form');
            form.method = 'GET';
            form.action = '/cookie-echo';
            document.body.appendChild(form);
            form.submit();
        });
        await testbench.waitForURL('**/cookie-echo*');
        const formGetResult = JSON.parse(await testbench.locator('body').innerText());
        expect(formGetResult.method).toBe('GET');
        expect(formGetResult.cookie).not.toContain('http_strict=1');
        for (const c of ['js_pre=1', 'http_default=1', 'http_lax=1', 'http_only=1']) {
            expect(formGetResult.cookie).toContain(c);
        }

        // 3. Enable `allow-same-origin` in the Report panel and verify ALL pre-existing cookies and cookie APIs work again!
        await testbench.goto('http://127.0.0.1:8123/');
        const report = await openPanel('report');
        await expect(report.locator('input#sandbox-enabled')).toBeChecked();
        await expect(report.locator('input#allow-scripts')).toBeChecked();
        await expect(report.locator('input#allow-forms')).toBeChecked();
        await expect(report.locator('input#allow-same-origin')).not.toBeChecked();

        await report.locator('input#allow-same-origin').check();
        await waitForPanelIdle(report);
        await testbench.reload();

        const withSameOrigin = await testbench.evaluate(async () => {
            const docCookieBeforeWrite = document.cookie;
            document.cookie = 'js_post=1; Path=/';
            const fetchEcho = await (await fetch('/cookie-echo?set_from_sub=allowed_now')).json();

            await new Promise((resolve) => {
                const img = new Image();
                img.onload = img.onerror = resolve;
                img.src = `/cookie-echo?record=1&t=${Date.now()}`;
            });
            const afterImg = await (await fetch('/cookie-echo')).json();

            // Verify other sandbox restrictions (like blocking window.open without allow-popups) remain active
            const popupResult = window.open('about:blank');

            return {
                origin: window.origin,
                docCookieBeforeWrite,
                docCookieAfterWrite: document.cookie,
                fetchCookie: fetchEcho.cookie,
                afterSubSetCookie: afterImg.cookie,
                imgSubresourceCookie: afterImg.last_subresource_cookie,
                popupBlocked: popupResult === null,
            };
        });

        expect(withSameOrigin.origin).toBe('http://127.0.0.1:8123');
        // Pre-existing cookies work immediately in document.cookie without needing to be re-set
        for (const c of ['js_pre=1', 'http_default=1', 'http_lax=1', 'http_strict=1']) {
            expect(withSameOrigin.docCookieBeforeWrite).toContain(c);
        }
        // Writing new cookies via document.cookie works
        expect(withSameOrigin.docCookieAfterWrite).toContain('js_post=1');
        // Same-origin fetch() and <img> subresources send all cookies (including SameSite=Strict and HttpOnly)
        for (const c of ['js_pre=1', 'js_post=1', 'http_default=1', 'http_lax=1', 'http_strict=1', 'http_only=1']) {
            expect(withSameOrigin.fetchCookie).toContain(c);
            expect(withSameOrigin.imgSubresourceCookie).toContain(c);
        }
        // Subresource Set-Cookie responses are accepted and stored again
        expect(withSameOrigin.afterSubSetCookie).toContain('sub_cookie=allowed_now');
        // Other sandbox restrictions (popups) are still enforced
        expect(withSameOrigin.popupBlocked).toBe(true);

        // And <form method="POST"> now sends all cookies (including SameSite=Strict) as a same-site request!
        await testbench.evaluate(() => {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/cookie-echo';
            document.body.appendChild(form);
            form.submit();
        });
        await testbench.waitForURL('**/cookie-echo');
        const formPostWithSameOrigin = JSON.parse(await testbench.locator('body').innerText());
        for (const c of [
            'js_pre=1',
            'js_post=1',
            'http_default=1',
            'http_lax=1',
            'http_strict=1',
            'http_only=1',
            'sub_cookie=allowed_now',
        ]) {
            expect(formPostWithSameOrigin.cookie).toContain(c);
        }

        // 4. Mode 3 (Sandbox: `sandbox` with no scripts) without vs. with `allow-same-origin`:
        //    Verify declarative subresources (/dot.png) withhold cookies without allow-same-origin,
        //    and send all cookies again when allow-same-origin is enabled (even with allow-scripts still off).
        await testbench.goto('http://127.0.0.1:8123/');
        await report.locator('button#abandon').click();
        await waitForPanelIdle(report);

        await setDefaultPolicy(serviceWorker, 3);
        await testbench.reload();

        const mode3WithoutSameOrigin = await report.evaluate(async () => {
            return (await fetch('http://127.0.0.1:8123/cookie-echo')).json();
        });
        // Top-level GET / sent cookies, but declarative subresource (/dot.png) sent none:
        expect(mode3WithoutSameOrigin.last_nav_cookie).toContain('http_strict=1');
        expect(mode3WithoutSameOrigin.last_subresource_cookie).toBe('');

        // Enable ONLY `allow-same-origin` (leaving `allow-scripts` unchecked) and reload:
        await expect(report.locator('input#sandbox-enabled')).toBeChecked();
        await expect(report.locator('input#allow-scripts')).not.toBeChecked();
        await report.locator('input#allow-same-origin').check();
        await waitForPanelIdle(report);
        await testbench.reload();

        const mode3WithSameOrigin = await report.evaluate(async () => {
            return (await fetch('http://127.0.0.1:8123/cookie-echo')).json();
        });
        for (const c of ['js_pre=1', 'js_post=1', 'http_default=1', 'http_lax=1', 'http_strict=1', 'http_only=1']) {
            expect(mode3WithSameOrigin.last_subresource_cookie).toContain(c);
        }
        // And scripts are still blocked on the page (#onload-summary remains at its initial static HTML text "23 Probes")
        await expect(testbench.locator('#onload-summary')).toHaveText('23 Probes');

        // Clean up cookies and session rule
        await report.locator('button#abandon').click();
        await waitForPanelIdle(report);
        await context.clearCookies();
    });

    test('<iframe> csp and sandbox attributes: additive intersection, CSPEE subsumption, and inability to weaken or bypass matrix³ CSP', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        // 1. <iframe csp="..."> under Mode 1 (First Party):
        //    Chromium's CheckCSPEmbeddedEnforcement has two enforcement paths for <iframe csp="...">:
        //    (A) Blanket enforcement (local schemes like srcdoc/blob:, OR network responses with `Allow-CSP-From: *`):
        //        Chromium adds `required_csp` to the subframe's PolicyContainer alongside matrix³'s response CSP.
        //        - A permissive `csp="default-src * 'unsafe-inline' 'unsafe-eval'"` cannot weaken matrix³'s `connect-src 'self'`.
        //        - A restrictive `csp="script-src 'none'"` or `csp="connect-src 'none'"` tightens the iframe additively.
        //    (B) Subsumption (`network::Subsumes`, when `Allow-CSP-From` is absent on network responses):
        //        - A permissive `csp="default-src * data: blob: 'unsafe-inline' 'unsafe-eval'"` subsumes matrix³'s First Party
        //          policy (ignoring matrix³'s appended `report-uri`), loads the frame, and still enforces matrix³'s `connect-src 'self'`.
        //        - A restrictive `csp="script-src 'none'"` that is not satisfied by the response's CSP fails subsumption
        //          and blocks the iframe response outright (`contentDocument === null`).
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.goto('http://127.0.0.1:8123/reset');

        const mode1IframeCsp = await testbench.evaluate(async () => {
            // (a) Blanket enforcement (`Allow-CSP-From: *`) + permissive csp attribute trying to allow cross-origin connect-src *
            const allowCspFromBypassAttempt = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.csp = "default-src * 'unsafe-inline' 'unsafe-eval'";
                const onMsg = (e) => {
                    if (e.source === ifr.contentWindow && e.data?.type === 'matrix3-frame' && 'fetch' in e.data) {
                        window.removeEventListener('message', onMsg);
                        resolve({
                            fetch: e.data.fetch,
                            scriptBadge: ifr.contentDocument?.getElementById('frame-script')?.textContent,
                        });
                    }
                };
                window.addEventListener('message', onMsg);
                ifr.src = `/frame.html?hdr=Allow-CSP-From&value=*&fetch=1&t=${Date.now()}`;
                document.body.appendChild(ifr);
            });

            // (b) Subsumption (no `Allow-CSP-From`) + permissive csp that subsumes First Party (including data: blob:)
            //     verifies matrix³'s appended `report-uri wss://_matrix3.internal/csp-report` does not break CSPEE subsumption,
            //     and matrix³'s `connect-src 'self'` is still enforced inside the frame.
            const subsumedBypassAttempt = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.csp = "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'";
                const onMsg = (e) => {
                    if (e.source === ifr.contentWindow && e.data?.type === 'matrix3-frame' && 'fetch' in e.data) {
                        window.removeEventListener('message', onMsg);
                        resolve({
                            fetch: e.data.fetch,
                            scriptBadge: ifr.contentDocument?.getElementById('frame-script')?.textContent,
                        });
                    }
                };
                window.addEventListener('message', onMsg);
                ifr.src = `/frame.html?fetch=1&t=${Date.now()}`;
                document.body.appendChild(ifr);
            });

            // (c) Local-scheme (`srcdoc`) + permissive csp attribute trying to allow cross-origin fetch
            const srcdocBypassAttempt = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.csp = "default-src * 'unsafe-inline' 'unsafe-eval'";
                const onMsg = (e) => {
                    if (e.source === ifr.contentWindow && e.data?.type === 'iframe-csp-srcdoc') {
                        window.removeEventListener('message', onMsg);
                        resolve(e.data.status);
                    }
                };
                window.addEventListener('message', onMsg);
                ifr.srcdoc = `<script>
                    fetch('https://untrusted.example.com/')
                        .then(() => parent.postMessage({ type: 'iframe-csp-srcdoc', status: 'allowed' }, '*'))
                        .catch(() => parent.postMessage({ type: 'iframe-csp-srcdoc', status: 'blocked' }, '*'));
                <\/script>`;
                document.body.appendChild(ifr);
            });

            // (d) Blanket enforcement (`Allow-CSP-From: *`) + restrictive csp="script-src 'none'" on /frame.html
            //     loads the HTML document and additively blocks its inline script (#frame-script stays "script: blocked").
            const restrictiveScriptNoneWithOptIn = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.csp = "script-src 'none'";
                ifr.onload = () => {
                    resolve(ifr.contentDocument?.getElementById('frame-script')?.textContent);
                };
                ifr.src = `/frame.html?hdr=Allow-CSP-From&value=*&t=${Date.now()}`;
                document.body.appendChild(ifr);
            });

            // (e) Subsumption failure (no `Allow-CSP-From`) + restrictive csp="script-src 'none'" on /frame.html:
            //     because First Party allows `script-src 'self' 'unsafe-inline' 'unsafe-eval'`, it is not subsumed by
            //     `script-src 'none'`, so Chromium blocks the frame navigation with ERR_BLOCKED_BY_CSP (contentDocument is null).
            const unsubsumedBlockedFrame = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.csp = "script-src 'none'";
                ifr.onload = () => {
                    resolve(ifr.contentDocument);
                };
                ifr.src = `/frame.html?t=${Date.now()}`;
                document.body.appendChild(ifr);
            });

            // (f) Restrictive csp="connect-src 'none'" on srcdoc blocks even same-origin fetch('/dot.png')
            const restrictiveConnectNone = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.csp = "connect-src 'none'";
                const onMsg = (e) => {
                    if (e.source === ifr.contentWindow && e.data?.type === 'iframe-csp-tighten') {
                        window.removeEventListener('message', onMsg);
                        resolve(e.data.status);
                    }
                };
                window.addEventListener('message', onMsg);
                ifr.srcdoc = `<script>
                    fetch('/dot.png')
                        .then(() => parent.postMessage({ type: 'iframe-csp-tighten', status: 'allowed' }, '*'))
                        .catch(() => parent.postMessage({ type: 'iframe-csp-tighten', status: 'blocked' }, '*'));
                <\/script>`;
                document.body.appendChild(ifr);
            });

            return {
                allowCspFromBypassAttempt,
                subsumedBypassAttempt,
                srcdocBypassAttempt,
                restrictiveScriptNoneWithOptIn,
                unsubsumedBlockedFrame,
                restrictiveConnectNone,
            };
        });

        expect(mode1IframeCsp).toEqual({
            allowCspFromBypassAttempt: { fetch: 'blocked', scriptBadge: 'script: allowed' },
            subsumedBypassAttempt: { fetch: 'blocked', scriptBadge: 'script: allowed' },
            srcdocBypassAttempt: 'blocked',
            restrictiveScriptNoneWithOptIn: 'script: blocked',
            unsubsumedBlockedFrame: null,
            restrictiveConnectNone: 'blocked',
        });

        // Verify violations inside the permissive-<iframe csp> frames were still reported to matrix³,
        // while the iframe-only `connect-src 'none'` on `/dot.png` did NOT report `'self'` under connect-src.
        const report = await openPanel('report');
        await expect(await getSourceCheckbox(report, 'https://*.github.com', 'connect-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'https://*.example.com', 'connect-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, "'self'", 'connect-src').locator()).not.toHaveClass(/violation/);

        // 2. <iframe sandbox="..."> under Mode 1 (First Party):
        //    - Restrictive `sandbox=""` blocks script execution even though First Party allows scripts.
        //    - `sandbox="allow-scripts"` (without `allow-same-origin`) forces an opaque origin ("null") and blocks document.cookie,
        //      while still enforcing matrix³'s `connect-src 'self'` inside the sandboxed frame.
        //    - Permissive `sandbox="allow-scripts allow-same-origin allow-forms allow-popups"` cannot bypass matrix³'s connect-src.
        const mode1IframeSandbox = await testbench.evaluate(async () => {
            // (a) Empty sandbox="" (with allow-same-origin only so we can inspect DOM) blocks scripts in /frame.html
            const noScriptsSandboxBadge = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.sandbox = 'allow-same-origin';
                ifr.onload = () => {
                    resolve(ifr.contentDocument?.getElementById('frame-script')?.textContent);
                };
                ifr.src = `/frame.html?t=${Date.now()}`;
                document.body.appendChild(ifr);
            });

            // (b) sandbox="allow-scripts" (no allow-same-origin) forces opaque origin ("null") & blocks document.cookie
            const opaqueSandbox = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.sandbox = 'allow-scripts';
                const onMsg = (e) => {
                    if (e.source === ifr.contentWindow && e.data?.type === 'iframe-sandbox-opaque') {
                        window.removeEventListener('message', onMsg);
                        resolve(e.data);
                    }
                };
                window.addEventListener('message', onMsg);
                ifr.srcdoc = `<script>
                    let cookieErr = null;
                    try { void document.cookie; } catch (e) { cookieErr = e.name; }
                    fetch('https://api.github.com/')
                        .then(() => parent.postMessage({ type: 'iframe-sandbox-opaque', origin: window.origin, cookieErr, fetch: 'allowed' }, '*'))
                        .catch(() => parent.postMessage({ type: 'iframe-sandbox-opaque', origin: window.origin, cookieErr, fetch: 'blocked' }, '*'));
                <\/script>`;
                document.body.appendChild(ifr);
            });

            // (c) Permissive sandbox="allow-scripts allow-same-origin allow-forms allow-popups" cannot bypass connect-src
            const permissiveSandboxFetch = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.sandbox = 'allow-scripts allow-same-origin allow-forms allow-popups';
                const onMsg = (e) => {
                    if (e.source === ifr.contentWindow && e.data?.type === 'matrix3-frame' && 'fetch' in e.data) {
                        window.removeEventListener('message', onMsg);
                        resolve(e.data.fetch);
                    }
                };
                window.addEventListener('message', onMsg);
                ifr.src = `/frame.html?fetch=1&t=${Date.now()}`;
                document.body.appendChild(ifr);
            });

            return { noScriptsSandboxBadge, opaqueSandbox, permissiveSandboxFetch };
        });

        expect(mode1IframeSandbox).toEqual({
            noScriptsSandboxBadge: 'script: blocked',
            opaqueSandbox: {
                type: 'iframe-sandbox-opaque',
                origin: 'null',
                cookieErr: 'SecurityError',
                fetch: 'blocked',
            },
            permissiveSandboxFetch: 'blocked',
        });

        // 3. Mode 2 (Sandbox-Lite: `sandbox allow-scripts allow-forms`, no `allow-same-origin`):
        //    An iframe with `sandbox="allow-scripts allow-same-origin"` and `csp="default-src * 'unsafe-inline'"`
        //    CANNOT regain same-origin access (`allow-same-origin` remains stripped by matrix³'s CSP sandbox header).
        await setDefaultPolicy(serviceWorker, 2);
        await testbench.reload();

        const mode2SandboxEscapeAttempt = await testbench.evaluate(async () => {
            return await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.sandbox = 'allow-scripts allow-same-origin';
                ifr.csp = "default-src * 'unsafe-inline' 'unsafe-eval'";
                const onMsg = (e) => {
                    if (e.source === ifr.contentWindow && e.data?.type === 'matrix3-frame') {
                        window.removeEventListener('message', onMsg);
                        let crossOriginAccessError = null;
                        try {
                            // Even though parent and child both loaded from http://127.0.0.1:8123 and the iframe
                            // specified sandbox="allow-scripts allow-same-origin", matrix³'s CSP sandbox directive
                            // forces each into a distinct opaque origin ("null"), so cross-frame access throws SecurityError!
                            void ifr.contentWindow.location.href;
                        } catch (err) {
                            crossOriginAccessError = err.name;
                        }
                        resolve({
                            parentOrigin: window.origin,
                            frameLoaded: e.data.status === 'loaded',
                            contentDocumentIsNull: ifr.contentDocument === null,
                            crossOriginAccessError,
                        });
                    }
                };
                window.addEventListener('message', onMsg);
                ifr.src = `/frame.html?hdr=Allow-CSP-From&value=*&t=${Date.now()}`;
                document.body.appendChild(ifr);
            });
        });

        expect(mode2SandboxEscapeAttempt).toEqual({
            parentOrigin: 'null',
            frameLoaded: true,
            contentDocumentIsNull: true,
            crossOriginAccessError: 'SecurityError',
        });

        // 4. Mode 4 (Strict: `default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:`):
        //    Allow `frame-src 'self'` so `/frame.html` can load, then verify that an iframe with BOTH
        //    `csp="default-src * data: 'unsafe-inline' 'unsafe-eval'"` AND `sandbox="allow-scripts allow-same-origin"`
        //    still has its scripts completely blocked by matrix³'s Strict policy on `/frame.html` (both via
        //    `Allow-CSP-From: *` blanket enforcement and via CSPEE subsumption) and on `srcdoc`.
        await setDefaultPolicy(serviceWorker, 4);
        await testbench.reload();
        await getSourceCheckbox(report, "'self'", 'frame-src').check();
        await waitForPanelIdle(report);
        await testbench.reload();

        const mode4BypassAttempt = await testbench.evaluate(async () => {
            const netFrameOptIn = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.csp = "default-src * 'unsafe-inline' 'unsafe-eval'";
                ifr.sandbox = 'allow-scripts allow-same-origin';
                ifr.onload = () => {
                    resolve(ifr.contentDocument?.getElementById('frame-script')?.textContent);
                };
                ifr.src = `/frame.html?hdr=Allow-CSP-From&value=*&t=${Date.now()}`;
                document.body.appendChild(ifr);
            });

            const netFrameSubsumed = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.csp = "default-src * data: 'unsafe-inline' 'unsafe-eval'";
                ifr.sandbox = 'allow-scripts allow-same-origin';
                ifr.onload = () => {
                    resolve(ifr.contentDocument?.getElementById('frame-script')?.textContent);
                };
                ifr.src = `/frame.html?t=${Date.now()}`;
                document.body.appendChild(ifr);
            });

            const srcdocFrame = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.csp = "default-src * 'unsafe-inline' 'unsafe-eval'";
                ifr.sandbox = 'allow-scripts allow-same-origin';
                ifr.onload = () => {
                    resolve(ifr.contentDocument?.getElementById('srcdoc-probe')?.textContent);
                };
                ifr.srcdoc = `<span id="srcdoc-probe">script: blocked</span><script>document.getElementById('srcdoc-probe').textContent = 'script: allowed';<\/script>`;
                document.body.appendChild(ifr);
            });

            return { netFrameOptIn, netFrameSubsumed, srcdocFrame };
        });

        expect(mode4BypassAttempt).toEqual({
            netFrameOptIn: 'script: blocked',
            netFrameSubsumed: 'script: blocked',
            srcdocFrame: 'script: blocked',
        });

        await report.locator('button#abandon').click();
        await waitForPanelIdle(report);
    });

    test('HTTP Link preload/modulepreload headers, X-Frame-Options preservation, <meta http-equiv="Content-Security-Policy">, Refresh, and <iframe credentialless>', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.goto('http://127.0.0.1:8123/reset');

        // 1. HTTP `Link:` response headers (`rel=preload; as=script`, `rel=modulepreload`, `rel=preload; as=fetch`)
        //    via both repeated `hdr=...&value=...` and indexed `hdr[1]=...&value[1]=...` query parameters:
        //    In Blink (`PreloadHelper::LoadLinksFromHeader`), resource-loading `Link` headers execute at
        //    `kDocumentAfterCommitWithoutViewport` after the document's `PolicyContainer` (including matrix³'s
        //    appended CSP) is committed, so cross-origin Link header preloads are blocked and reported.
        await testbench.evaluate(async () => {
            await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                const params = new URLSearchParams();
                params.append('hdr', 'Link');
                params.append('value', '<https://link-preload.example.net/app.js>; rel=preload; as=script');
                params.append('hdr[1]', 'Link');
                params.append('value[1]', '<https://link-module.example.org/mod.js>; rel=modulepreload');
                params.append('hdr[2]', 'Link');
                params.append('value[2]', '<https://link-fetch.example.com/data.json>; rel=preload; as=fetch; crossorigin');
                params.append('t', String(Date.now()));
                ifr.onload = resolve;
                ifr.src = `/frame.html?${params.toString()}`;
                document.body.appendChild(ifr);
            });
        });

        const report = await openPanel('report');
        await expect(await getSourceCheckbox(report, 'https://*.example.net', 'script-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'https://*.example.org', 'script-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'https://*.example.com', 'connect-src').locator()).toHaveClass(/violation/);

        // 2. Interactive Header Builder UI (`#header-builder-name`, `#header-builder-value`, custom "Other…", `#headers`)
        //    and `X-Frame-Options: DENY` preservation (`AncestorThrottle::EvaluateXFrameOptions`):
        //    In Chromium (`ancestor_throttle.cc`), any enforced `Content-Security-Policy` header with a
        //    `frame-ancestors` directive causes Chromium to ignore `X-Frame-Options`.
        //    Verify that even if a server sends `frame-ancestors *` and the user clicks Accept (#accept),
        //    `Policy.sanitizeForAppend()` strips `frame-ancestors` from matrix³'s appended dNR rule so
        //    a response with `X-Frame-Options: DENY` (`/frame.html?hdr=X-Frame-Options&value=DENY`) is still blocked!
        await testbench.locator('#csp').fill("default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors *");
        await testbench.locator('#header-builder-name').selectOption('Link');
        await testbench.locator('#header-builder-value').selectOption('__other__');
        await testbench.locator('#header-builder-custom-value').fill('<https://hdr-builder.example.edu/preload.js>; rel=preload; as=script');
        await testbench.locator('#header-builder-append-btn').click();
        await testbench.locator('#header-builder-name').selectOption('__other__');
        await testbench.locator('#header-builder-custom-name').fill('X-Testbench-Custom');
        await testbench.locator('#header-builder-custom-value').fill('enabled');
        await testbench.locator('#header-builder-append-btn').click();
        await testbench.locator('form.csp-form button[type="submit"]').click();

        await expect(await getSourceCheckbox(report, 'https://*.example.edu', 'script-src').locator()).toHaveClass(/violation/);

        const details = report.locator('div#serverpolicy details');
        await expect(details).toBeVisible();
        await details.locator('summary').click();
        await report.locator('button#accept').click();
        await waitForPanelIdle(report);

        const xfoBlocked = await testbench.evaluate(async () => {
            return await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.onload = () => resolve(ifr.contentDocument === null);
                ifr.src = `/frame.html?hdr=X-Frame-Options&value=DENY&t=${Date.now()}`;
                document.body.appendChild(ifr);
            });
        });
        expect(xfoBlocked).toBe(true);

        await report.locator('button#abandon').click();
        await waitForPanelIdle(report);

        // 3. `<meta http-equiv="Content-Security-Policy">` (`HttpEquiv::ProcessHttpEquivContentSecurityPolicy`):
        //    - A permissive `<meta http-equiv="Content-Security-Policy" content="default-src * data: blob: 'unsafe-inline' 'unsafe-eval'">`
        //      cannot loosen matrix³'s HTTP response CSP (nor in a child `about:blank` frame that inherits the parent's PolicyContainer).
        //    - A restrictive `<meta http-equiv="Content-Security-Policy" content="connect-src 'none'">` tightens the frame additively.
        const metaCspResults = await testbench.evaluate(async () => {
            // (a) Permissive <meta http-equiv="Content-Security-Policy"> trying to allow cross-origin connect-src *
            const permissiveMetaBypass = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                const onMsg = (e) => {
                    if (e.source === ifr.contentWindow && e.data?.type === 'meta-csp-bypass') {
                        window.removeEventListener('message', onMsg);
                        resolve(e.data);
                    }
                };
                window.addEventListener('message', onMsg);
                ifr.srcdoc = `<!doctype html><html><head>
                    <meta http-equiv="Content-Security-Policy" content="default-src * data: blob: 'unsafe-inline' 'unsafe-eval'">
                </head><body><script>
                    (async () => {
                        let directFetch = 'allowed';
                        try {
                            await fetch('https://meta-bypass.invalid/');
                        } catch {
                            directFetch = 'blocked';
                        }
                        // Also test a child about:blank iframe created after the <meta> policy was added to PolicyContainer
                        const child = document.createElement('iframe');
                        document.body.appendChild(child);
                        let childFetch = 'allowed';
                        try {
                            await child.contentWindow.fetch('https://meta-child-bypass.invalid/');
                        } catch {
                            childFetch = 'blocked';
                        }
                        parent.postMessage({ type: 'meta-csp-bypass', directFetch, childFetch }, '*');
                    })();
                <\/script></body></html>`;
                document.body.appendChild(ifr);
            });

            // (b) Restrictive <meta http-equiv="Content-Security-Policy" content="connect-src 'none'"> blocks same-origin /dot.png
            const restrictiveMetaTighten = await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                const onMsg = (e) => {
                    if (e.source === ifr.contentWindow && e.data?.type === 'meta-csp-tighten') {
                        window.removeEventListener('message', onMsg);
                        resolve(e.data.status);
                    }
                };
                window.addEventListener('message', onMsg);
                ifr.srcdoc = `<!doctype html><html><head>
                    <meta http-equiv="Content-Security-Policy" content="connect-src 'none'">
                </head><body><script>
                    fetch('/dot.png')
                        .then(() => parent.postMessage({ type: 'meta-csp-tighten', status: 'allowed' }, '*'))
                        .catch(() => parent.postMessage({ type: 'meta-csp-tighten', status: 'blocked' }, '*'));
                <\/script></body></html>`;
                document.body.appendChild(ifr);
            });

            return { permissiveMetaBypass, restrictiveMetaTighten };
        });

        expect(metaCspResults).toEqual({
            permissiveMetaBypass: {
                type: 'meta-csp-bypass',
                directFetch: 'blocked',
                childFetch: 'blocked',
            },
            restrictiveMetaTighten: 'blocked',
        });

        // 4. `<iframe credentialless>` (`commit_params_->is_credentialless`):
        //    Verify an `<iframe credentialless>` subframe still receives matrix³'s appended CSP and blocks/reports violations.
        const credentiallessResult = await testbench.evaluate(async () => {
            return await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.credentialless = true;
                const onMsg = (e) => {
                    if (e.source === ifr.contentWindow && e.data?.type === 'matrix3-frame' && 'fetch' in e.data) {
                        window.removeEventListener('message', onMsg);
                        resolve({
                            credentialless: ifr.credentialless,
                            fetch: e.data.fetch,
                        });
                    }
                };
                window.addEventListener('message', onMsg);
                ifr.src = `/frame.html?fetch=1&t=${Date.now()}`;
                document.body.appendChild(ifr);
            });
        });
        expect(credentiallessResult).toEqual({
            credentialless: true,
            fetch: 'blocked',
        });

        // 5. `Refresh:` HTTP response header & `<meta http-equiv="refresh">` (`Document::MaybeHandleHttpRefresh`):
        //    - `Refresh: 0; url=javascript:...` HTTP header and `<meta http-equiv="refresh" content="0; url=javascript:...">`
        //      are refused by Chromium and never execute JS.
        //    - Under Mode 3 (Sandbox: `Content-Security-Policy: sandbox` without `allow-scripts`),
        //      `<meta http-equiv="refresh" content="0; url=/frame.html">` is blocked by `WebSandboxFlags::kAutomaticFeatures`.
        const jsRefreshBlocked = await testbench.evaluate(async () => {
            return await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.onload = () => {
                    setTimeout(() => {
                        resolve(Boolean(ifr.contentWindow?.__jsRefreshExecuted));
                    }, 150);
                };
                ifr.src = `/frame.html?hdr=Refresh&value=${encodeURIComponent('0; url=javascript:window.__jsRefreshExecuted=true')}&t=${Date.now()}`;
                document.body.appendChild(ifr);
            });
        });
        expect(jsRefreshBlocked).toBe(false);

        await setDefaultPolicy(serviceWorker, 3);
        await testbench.goto('http://127.0.0.1:8123/reset');
        await testbench.evaluate(() => {
            const ifr = document.createElement('iframe');
            ifr.id = 'sandbox-meta-refresh-probe';
            ifr.srcdoc = `<!doctype html><html><head>
                <meta http-equiv="refresh" content="0; url=/frame.html?meta_refresh_escaped=1">
            </head><body>sandboxed meta refresh</body></html>`;
            document.body.appendChild(ifr);
        });
        await testbench.waitForTimeout(300);
        // Under Mode 3 (CSP `sandbox`), `<meta http-equiv="refresh">` is blocked by kAutomaticFeatures
        // (so no frame ever navigates to `/frame.html?meta_refresh_escaped=1`).
        const escapedFrames = testbench.frames().filter((f) => f.url().includes('meta_refresh_escaped=1'));
        expect(escapedFrames).toHaveLength(0);
    });

    test('nonsense hostnames with CSP delimiters (;, ", \', ,), IPv6 literals, trailing-dot FQDNs, and IDNs are validated via psl/tldts', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1); // First Party (blocks cross-origin script-src and connect-src)
        await testbench.goto('http://127.0.0.1:8123/reset');

        // 1. Send Link: <https://testing.";script-src'self';".com/x.js>; rel=preload; as=script via Header Builder
        await testbench.locator('#header-builder-name').selectOption('Link');
        await testbench.locator('#header-builder-value').selectOption('__other__');
        await testbench
            .locator('#header-builder-custom-value')
            .fill('<https://testing.";script-src\'self\';".com/x.js>; rel=preload; as=script');
        await testbench.locator('#header-builder-append-btn').click();
        await testbench.locator('form.csp-form button[type="submit"]').click();

        // 2. Trigger subresource loads with ';', '"', '%22', "'", ',', IPv6 [::1], trailing-dot FQDNs, and IDN
        await testbench.evaluate(() => {
            for (const url of [
                'https://testing.";script-src\'self\';".com/a.js',
                'https://testing.%22;script-src\'self\';%22.com/b.js',
                'https://testing.;sandbox;.com/c.js',
                'https://testing.,default-src.com/d.js',
                'http://[::1]:8123/ipv6.js',
                'https://example.com./fqdn-apex.js',
                'https://münchen.de/idn.js',
            ]) {
                fetch(url).catch(() => {});
            }
        });

        const report = await openPanel('report');
        // Trailing-dot apex `https://example.com./` must normalize to `https://example.com` (NOT `https://*.example.com`),
        // and IDN `https://münchen.de/` normalizes to punycode `https://xn--mnchen-3ya.de`.
        await expect(await getSourceCheckbox(report, 'https://example.com', 'connect-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'https://xn--mnchen-3ya.de', 'connect-src').locator()).toHaveClass(/violation/);

        // None of the nonsense hostnames with ';', '"', "'", ',', or IPv6 '[::1]' / '::1' may appear in the Report panel
        const rowTitles = await report
            .locator('table#sources tbody tr th')
            .evaluateAll((ths) => ths.map((th) => th.title));
        expect(rowTitles.filter((t) => t.includes('testing.') || t.includes('::1'))).toEqual([]);
        expect(rowTitles).not.toContain('https://*.example.com');

        // 3. Direct unit check on psl.getHostname / getRegistrableDomain / getScopedDomain edge cases
        const pslChecks = await report.evaluate(async () => {
            const psl = await import('/include/psl.js');
            return {
                fqdnApexDomain: await psl.getScopedDomain('example.com.'),
                fqdnApexHost: psl.getHostname('example.com.'),
                fqdnSubDomain: await psl.getScopedDomain('sub.example.com.'),
                fqdnSubHost: psl.getHostname('sub.example.com.'),
                ipv4: await psl.getScopedDomain('127.0.0.1'),
                localhost: await psl.getScopedDomain('localhost'),
                ipv6Bracketed: await psl.getScopedDomain('[::1]'),
                ipv6Bare: await psl.getScopedDomain('::1'),
                semicolonHost: await psl.getScopedDomain('testing.";script-src\'self\';".com'),
                commaHost: await psl.getScopedDomain('testing.,default-src.com'),
                rtlHost: await psl.getScopedDomain('ex\u202eample.com'),
                leadingHyphen: await psl.getScopedDomain('-leading.com'),
                trailingHyphen: await psl.getScopedDomain('trailing-.com'),
                emptyLabel: await psl.getScopedDomain('empty..label.com'),
            };
        });
        expect(pslChecks).toEqual({
            fqdnApexDomain: 'example.com',
            fqdnApexHost: 'example.com',
            fqdnSubDomain: 'example.com',
            fqdnSubHost: 'sub.example.com',
            ipv4: '127.0.0.1',
            localhost: 'localhost',
            ipv6Bracketed: null,
            ipv6Bare: null,
            semicolonHost: null,
            commaHost: null,
            rtlHost: null,
            leadingHyphen: null,
            trailingHyphen: null,
            emptyLabel: null,
        });
    });
});
