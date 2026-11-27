import {
    test,
    expect,
    setDefaultPolicy,
    waitForPanelIdle,
    getOnloadBadges,
    getReportedViolations,
    getSourceCheckbox,
} from './fixtures.js';

test.describe('Special Contexts, Redirects, Schemes, Subframes, & Resource Caps', () => {
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

    test('cross-origin blob: subframe navigation (SafeContentFrame) reports blob: instead of data: in frame-src', async ({ serviceWorker, testbench, openPanel }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        const report = await openPanel('report');
        await getSourceCheckbox(report, "'self'", 'frame-src').check();
        await getSourceCheckbox(report, 'data:', 'frame-src').check();
        await getSourceCheckbox(report, 'http:', 'frame-src').check();

        await Promise.all([
            testbench.waitForNavigation(),
            report.locator('button#reload').click(),
        ]);

        await testbench.locator('#scheme-select').selectOption('frame:cross-blob');
        await testbench.locator('#weird-schemes-btn').click();

        await expect(await getSourceCheckbox(report, 'blob:', 'frame-src').locator()).toHaveClass(/violation/, { timeout: 3000 });
        await expect(await getSourceCheckbox(report, 'data:', 'frame-src').locator()).not.toHaveClass(/violation/);

        // Allowing blob: in frame-src lets the cross-origin SafeContentFrame blob: navigation succeed,
        // and an unsupported custom scheme (frame:custom) does not falsely re-flag data: or blob:.
        await getSourceCheckbox(report, 'blob:', 'frame-src').check();
        await Promise.all([
            testbench.waitForNavigation(),
            report.locator('button#reload').click(),
        ]);

        await testbench.locator('#scheme-select').selectOption('frame:cross-blob');
        await testbench.locator('#weird-schemes-btn').click();
        await expect(testbench.frameLocator('#special-out iframe').locator('body')).toContainText('cross-origin blob: frame loaded');

        await testbench.locator('#scheme-select').selectOption('frame:custom');
        await testbench.locator('#weird-schemes-btn').click();
        await expect(await getSourceCheckbox(report, 'data:', 'frame-src').locator()).not.toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'blob:', 'frame-src').locator()).not.toHaveClass(/violation/);
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
            ipv6Bracketed: '[::1]',
            ipv6Bare: null,
            semicolonHost: null,
            commaHost: null,
            rtlHost: null,
            leadingHyphen: null,
            trailingHyphen: null,
            emptyLabel: null,
        });
    });

    test('1. subframe with an invalid hostname does not create a "null" origin button in div#frames', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 0); // Permissive so cross-origin subframes can navigate
        await testbench.goto('http://127.0.0.1:8123/reset');

        await testbench.evaluate(async () => {
            await new Promise((resolve) => {
                const ifr = document.createElement('iframe');
                ifr.onload = ifr.onerror = resolve;
                ifr.src = 'https://testing.";script-src;".com/';
                document.body.appendChild(ifr);
            });
        });

        const report = await openPanel('report');
        const frameButtons = await report
            .locator('div#frames button[data-value]')
            .evaluateAll((btns) => btns.map((b) => b.dataset.value));
        expect(frameButtons).toEqual(['127.0.0.1', 'example.com']);
        expect(frameButtons).not.toContain('null');
    });

    test('3. multi-hop #fragment redirect chains resolve to the final target end-to-end', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.goto('http://127.0.0.1:8123/reset');

        const report = await openPanel('report');
        // Allow http://localhost:8123 in script-src so Hop 1 (/redirect) -> Hop 2 (localhost/redirect#frag1)
        // is allowed, and only the final hop (https://cdn.jsdelivr.net/...#frag2) is blocked by script-src.
        await testbench.evaluate(async () => {
            await fetch('http://localhost:8123/dot.png').catch(() => {});
        });
        await getSourceCheckbox(report, 'http://localhost:8123', 'script-src').check();
        await testbench.reload();

        await testbench.evaluate(async () => {
            const hop2 = 'http://localhost:8123/redirect?to=' +
                encodeURIComponent('https://cdn.jsdelivr.net/npm/d3/%2Besm#frag2') +
                '#frag1';
            const hop1 = '/redirect?to=' + encodeURIComponent(hop2) + '#frag0';
            await new Promise((resolve) => {
                const s = document.createElement('script');
                s.onload = s.onerror = resolve;
                s.src = hop1;
                document.head.appendChild(s);
            });
        });

        await expect(await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'script-src').locator()).toHaveClass(
            /\bviolation\b/
        );

        // Cyclic redirect chain (A <-> B) terminates cleanly at the 20-hop cap
        const cycleDirs = await report.evaluate(async () => {
            const { default: ViolationTracker } = await import('/include/tracker.js');
            const vt = new ViolationTracker();
            await vt.resetViolations(9997);
            await vt.addDocument(9997, 'doc-0', 'https://app.example.com/');
            await vt.addRedirect(9997, 'https://cycle-a.example.test/loop', 'https://cycle-b.example.test/loop');
            await vt.addRedirect(9997, 'https://cycle-b.example.test/loop', 'https://cycle-a.example.test/loop');
            await vt.addTabViolation(9997, {
                report: { 'document-uri': 'https://app.example.com/' },
                directive: 'connect-src',
                blocked: new URL('https://cycle-a.example.test/loop'),
                documentId: 'doc-0',
            });
            const dirs = await vt.getDirectives(9997, 'example.com');
            await vt.resetTab(9997);
            return dirs['connect-src'] ?? [];
        });
        expect(cycleDirs).toEqual(['https://*.example.test']);
    });

    test('3b. unrelated subresource redirect from an origin does not hijack frame-src or object-src violations on that origin', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.goto('http://127.0.0.1:8123/reset');

        const report = await openPanel('report');
        // Allow http://localhost:8123 in script-src (so a script from localhost can 302-redirect to jsdelivr),
        // while leaving http://localhost:8123 blocked in frame-src and object-src.
        await testbench.evaluate(async () => {
            await fetch('http://localhost:8123/dot.png').catch(() => {});
        });
        await getSourceCheckbox(report, 'http://localhost:8123', 'script-src').check();
        await testbench.reload();

        // 1. Load an allowed script from http://localhost:8123/redirect that 302-redirects to jsdelivr
        await testbench.evaluate(async () => {
            await new Promise((resolve) => {
                const s = document.createElement('script');
                s.onload = s.onerror = resolve;
                s.src = 'http://localhost:8123/redirect?to=https://cdn.jsdelivr.net/npm/d3/%2Besm';
                document.head.appendChild(s);
            });
        });

        // 2. Direct (non-redirecting) cross-origin <iframe> and <object> to http://localhost:8123/frame.html
        //    must report http://localhost:8123 in frame-src and object-src, NOT be hijacked by jsdelivr!
        await testbench.evaluate(() => {
            const ifr = document.createElement('iframe');
            ifr.src = 'http://localhost:8123/frame.html';
            document.body.appendChild(ifr);

            const obj = document.createElement('object');
            obj.data = 'http://localhost:8123/frame.html';
            document.body.appendChild(obj);
        });

        await expect(await getSourceCheckbox(report, 'http://localhost:8123', 'frame-src').locator()).toHaveClass(
            /\bviolation\b/
        );
        await expect(await getSourceCheckbox(report, 'http://localhost:8123', 'object-src').locator()).toHaveClass(
            /\bviolation\b/
        );
        await expect(await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'frame-src').locator()).not.toHaveClass(
            /\bviolation\b/
        );
        await expect(await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'object-src').locator()).not.toHaveClass(
            /\bviolation\b/
        );

        // 3. Same-origin -> cross-origin sub_frame redirect (/redirect -> https://cdn.jsdelivr.net/...)
        //    reports https://*.jsdelivr.net in frame-src
        await testbench.evaluate(() => {
            const ifr = document.createElement('iframe');
            ifr.src = '/redirect?to=https://cdn.jsdelivr.net/npm/d3/%2Besm';
            document.body.appendChild(ifr);
        });
        await expect(await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'frame-src').locator()).toHaveClass(
            /\bviolation\b/
        );

        // 4. Cross-origin -> cross-origin sub_frame and <object> redirects
        //    (http://localhost:8123/redirect -> https://cdn.jsdelivr.net/...)
        //    both report https://*.jsdelivr.net in frame-src (Chromium's browser-process
        //    NavigationRequest::CheckCSPDirectives checks frame-src on <object> navigation redirects)
        await getSourceCheckbox(report, 'http://localhost:8123', 'frame-src').check();
        await getSourceCheckbox(report, 'http://localhost:8123', 'object-src').check();
        await testbench.reload();
        await testbench.evaluate(() => {
            const ifr = document.createElement('iframe');
            ifr.src = 'http://localhost:8123/redirect?to=https://cdn.jsdelivr.net/npm/d3/%2Besm';
            document.body.appendChild(ifr);
        });
        await expect(await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'frame-src').locator()).toHaveClass(
            /\bviolation\b/
        );

        await testbench.reload();
        await testbench.evaluate(() => {
            const obj = document.createElement('object');
            obj.data = 'http://localhost:8123/redirect?to=https://cdn.jsdelivr.net/npm/d3/%2Besm';
            document.body.appendChild(obj);
        });
        await expect(await getSourceCheckbox(report, 'https://*.jsdelivr.net', 'frame-src').locator()).toHaveClass(
            /\bviolation\b/
        );
    });

    test('4. <fencedframe> violations (effective-directive: "fenced-frame-src") collapse to frame-src', async ({
        openPanel,
    }) => {
        const panel = await openPanel('options');
        const collapsed = await panel.evaluate(async () => {
            const { default: Policy } = await import('/include/policy.js');
            return Policy.collapseDirective('fenced-frame-src');
        });
        expect(collapsed).toBe('frame-src');
    });
});
