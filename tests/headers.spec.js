import {
    test,
    expect,
    setDefaultPolicy,
    waitForPanelIdle,
    getOnloadBadges,
    getReportedViolations,
    getSourceCheckbox,
} from './fixtures.js';

test.describe('Server CSP, Additive Intersection, Cookies, & Response Headers', () => {
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

        // 6. `Speculation-Rules:` HTTP response header (`DocumentSpeculationRules::From` / crbug.com/590725419):
        //    Unlike `<script type="speculationrules">`, the `Speculation-Rules` HTTP header is not governed by
        //    any CSP directive (even `default-src 'none'` or `sandbox`) and can evaluate arbitrary CSS selectors
        //    (`where: { selector_matches: ... }`) to trigger prefetches. Verify rule 3 in `base.json` strips
        //    `Speculation-Rules` from responses so no prefetch is triggered.
        await setDefaultPolicy(serviceWorker, 4); // Strict (`default-src 'none'`)
        await testbench.goto('http://127.0.0.1:8123/reset');
        const specRulesPrefetches = [];
        const onSpecRequest = (req) => {
            if (req.url().includes('/frame.html?spec_prefetch=')) {
                specRulesPrefetches.push({
                    url: req.url(),
                    secPurpose: req.headers()['sec-purpose'] ?? '',
                });
            }
        };
        testbench.on('request', onSpecRequest);
        try {
            const specRuleJson = JSON.stringify({
                prefetch: [
                    {
                        source: 'document',
                        where: { selector_matches: 'a[href*="spec_prefetch"]' },
                        eagerness: 'immediate',
                    },
                    {
                        source: 'list',
                        urls: ['/frame.html?spec_prefetch=list'],
                        eagerness: 'immediate',
                    },
                ],
            });
            const specHeaderVal = `"data:application/speculationrules+json;base64,${Buffer.from(specRuleJson).toString('base64')}"`;
            await testbench.goto(
                `http://127.0.0.1:8123/?hdr=Speculation-Rules&value=${encodeURIComponent(specHeaderVal)}`
            );
            await testbench.waitForTimeout(300);
            expect(specRulesPrefetches).toEqual([]);
        } finally {
            testbench.off('request', onSpecRequest);
        }

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

    test('2. server script-src-attr \'none\' / style-src-attr \'none\' does not check \'none\' in script-src / style-src or disable scripts/styles on Merge', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.goto('http://127.0.0.1:8123/reset');

        await testbench
            .locator('#csp')
            .fill(
                "script-src 'self' https://cdn.jsdelivr.net; script-src-attr 'none'; style-src-attr 'none'; fake-attr https://evil.example.com; img-src-attr https://evil2.example.com"
            );
        await testbench.locator('form.csp-form button[type="submit"]').click();

        const report = await openPanel('report');
        const details = report.locator('div#serverpolicy details');
        await expect(details).toBeVisible();
        await details.locator('summary').click();

        // In #serversources, 'self' and 'https://cdn.jsdelivr.net' are checked in script-src,
        // 'none' must NOT be checked in script-src or style-src, and fake-attr / img-src-attr
        // must not populate any source rows in #serversources.
        await expect(await getSourceCheckbox(report, "'self'", 'script-src', 'table#serversources').locator()).toBeChecked();
        await expect(
            await getSourceCheckbox(report, 'https://cdn.jsdelivr.net', 'script-src', 'table#serversources').locator()
        ).toBeChecked();
        const serverScriptNone = report.locator('table#serversources tbody tr th[title="\'none\'"]');
        await expect(serverScriptNone).toHaveCount(0);
        await expect(report.locator('table#serversources tbody tr th[title*="evil"]')).toHaveCount(0);

        // Clicking Merge must keep 'self' and 'https:' checked in style-src (not wipe them out with 'none'!)
        await report.locator('button#merge').click();
        await waitForPanelIdle(report);
        await expect(await getSourceCheckbox(report, "'self'", 'style-src').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, 'https:', 'style-src').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, "'none'", 'style-src').locator()).not.toBeChecked();

        await report.locator('button#abandon').click();
        await waitForPanelIdle(report);
    });

    test('5. uppercase hostnames in Server CSP headers are normalized to lowercase so Accept/Merge does not create duplicate rows', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.goto('http://127.0.0.1:8123/reset');

        await testbench.locator('#csp').fill("script-src 'self' https://CDN.JSDelivr.NET/npm/d3/+esm");
        await testbench.locator('form.csp-form button[type="submit"]').click();

        const report = await openPanel('report');
        const details = report.locator('div#serverpolicy details');
        await expect(details).toBeVisible();
        await details.locator('summary').click();

        await expect(
            await getSourceCheckbox(report, 'https://cdn.jsdelivr.net', 'script-src', 'table#serversources').locator()
        ).toBeChecked();
        await expect(report.locator('table#serversources tbody tr th[title="https://CDN.JSDelivr.NET"]')).toHaveCount(0);
    });

    test('6. Policy.sanitizeForAppend() strips invalid source tokens and fake-attr directives', async ({ openPanel }) => {
        const panel = await openPanel('options');
        const sanitized = await panel.evaluate(async () => {
            const { default: Policy } = await import('/include/policy.js');
            return new Policy(
                "script-src 'self' 'bogus-token' https://bad\"host.com https://cdn.jsdelivr.net; img-src 'self' data: ???; fake-attr 'self'; img-src-attr 'self'"
            )
                .sanitizeForAppend()
                .toHeader()
                .trim();
        });
        expect(sanitized).toBe("script-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:;");
    });
});
