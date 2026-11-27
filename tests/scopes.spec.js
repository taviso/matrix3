import {
    test,
    expect,
    setDefaultPolicy,
    setOptions,
    waitForPanelIdle,
    getOnloadBadges,
    getReportedViolations,
    getSourceCheckbox,
} from './fixtures.js';

test.describe('Scopes, Subdomain Priority, Private Domains, IPv6, & Untrusted Input Rendering', () => {
    test('Domain vs. Host scope: rule inheritance, exact-host button states, label-scaled priority overrides (10*L + tier), and mode switching', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await setOptions(serviceWorker, { defaultscope: 'domain' });

        // 1. In Domain mode, navigate to http://sub.testbench.com:8123/
        await testbench.goto('http://sub.testbench.com:8123/');
        await getOnloadBadges(testbench);
        const report = await openPanel('report');

        // Origin tab collapses sub.testbench.com -> testbench.com, and subresources collapse to *.domain
        await expect(report.locator('#frames button.active')).toHaveAttribute('data-value', 'testbench.com');
        const domainViolations = await getReportedViolations(report);
        expect(domainViolations['https://*.google.com']).toEqual(
            expect.arrayContaining(['script-src', 'media-src'])
        );
        expect(domainViolations['https://*.github.com']).toEqual(['connect-src']);

        // Allow https://*.google.com in script-src on testbench.com and Commit
        await getSourceCheckbox(report, 'https://*.google.com', 'script-src').check();
        await report.locator('#commit').click();
        await waitForPanelIdle(report);

        await testbench.reload();
        expect((await getOnloadBadges(testbench))['ext-script']).toBe('Allowed');

        // 2. Switch to Host mode via Options panel and reload http://sub.testbench.com:8123/
        const optionsPanel = await openPanel('options');
        await optionsPanel.locator('#defaultscope').selectOption('host');
        await testbench.bringToFront();
        await testbench.reload();
        await getOnloadBadges(testbench);
        await waitForPanelIdle(report);

        // Origin tab is now literal host sub.testbench.com
        await expect(report.locator('#frames button.active')).toHaveAttribute('data-value', 'sub.testbench.com');

        // getHostRule("sub.testbench.com") walks parent labels and inherits testbench.com's committed rule!
        await expect(await getSourceCheckbox(report, 'https://*.google.com', 'script-src').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, 'https://*.google.com', 'script-src').locator()).toHaveClass(/\bdynamic\b/);
        expect((await getOnloadBadges(testbench))['ext-script']).toBe('Allowed');

        // Because sub.testbench.com has no rule of its own yet (it inherits testbench.com),
        // updateButtonStates disables #commit, #uncommit, #abandon, and #reset
        await expect(report.locator('#commit')).toBeDisabled();
        await expect(report.locator('#uncommit')).toBeDisabled();
        await expect(report.locator('#abandon')).toBeDisabled();
        await expect(report.locator('#reset')).toBeDisabled();

        // Violations in Host mode use exact hostnames (no *. prefix)
        const hostViolations = await getReportedViolations(report);
        expect(hostViolations['https://api.github.com']).toEqual(['connect-src']);
        expect(hostViolations['https://actions.google.com']).toEqual(['media-src']);
        expect(hostViolations['https://*.github.com']).toBeUndefined();

        // 3. Create a host-specific rule on sub.testbench.com (L=3, priority 31..34) that:
        //    - Tightens script-src by unchecking https://*.google.com (inherited from testbench.com)
        //    - Loosens connect-src by checking https://api.github.com
        await getSourceCheckbox(report, 'https://*.google.com', 'script-src').uncheck();
        await getSourceCheckbox(report, 'https://api.github.com', 'connect-src').check();

        // Now sub.testbench.com has its own session rule -> #commit, #abandon, and #reset are enabled
        await expect(report.locator('#commit')).toBeEnabled();
        await expect(report.locator('#abandon')).toBeEnabled();
        await expect(report.locator('#reset')).toBeEnabled();

        await testbench.reload();
        const subBadges = await getOnloadBadges(testbench);
        expect(subBadges['ext-script']).toBe('Blocked');
        expect(subBadges['fetch']).toBe('Allowed');

        // Commit sub.testbench.com's rule to dynamic (priority 31..32)
        await report.locator('#commit').click();
        await waitForPanelIdle(report);

        // 4. Deeper subdomain http://deep.sub.testbench.com:8123/ (L=4) inherits from closest ancestor
        //    sub.testbench.com (L=3) rather than testbench.com (L=2), and can override it at priority 41..44
        await testbench.goto('http://deep.sub.testbench.com:8123/');
        const deepInheritedBadges = await getOnloadBadges(testbench);
        await waitForPanelIdle(report);
        await expect(report.locator('#frames button.active')).toHaveAttribute('data-value', 'deep.sub.testbench.com');
        expect(deepInheritedBadges['ext-script']).toBe('Blocked');
        expect(deepInheritedBadges['fetch']).toBe('Allowed');

        // Override on deep.sub.testbench.com: allow https://www.google.com in script-src
        await getSourceCheckbox(report, 'https://www.google.com', 'script-src').check();
        await testbench.reload();
        const deepOverriddenBadges = await getOnloadBadges(testbench);
        expect(deepOverriddenBadges['ext-script']).toBe('Allowed');
        expect(deepOverriddenBadges['fetch']).toBe('Allowed');

        // 5. Sibling subdomain http://other.testbench.com:8123/ still inherits testbench.com (L=2):
        //    ext-script is Allowed, fetch is Blocked
        await testbench.goto('http://other.testbench.com:8123/');
        await waitForPanelIdle(report);
        await expect(report.locator('#frames button.active')).toHaveAttribute('data-value', 'other.testbench.com');
        const otherBadges = await getOnloadBadges(testbench);
        expect(otherBadges['ext-script']).toBe('Allowed');
        expect(otherBadges['fetch']).toBe('Blocked');

        // Verify dNR rule priorities across L=2 (testbench.com: 21,22), L=3 (sub.testbench.com: 31,32), and L=4 (deep.sub.testbench.com: 43,44)
        const dnrPriorities = await serviceWorker.evaluate(async () => {
            const [dyn, sess] = await Promise.all([
                chrome.declarativeNetRequest.getDynamicRules(),
                chrome.declarativeNetRequest.getSessionRules(),
            ]);
            return [...dyn, ...sess].map((r) => ({
                filter: r.condition.urlFilter,
                type: r.action.type,
                priority: r.priority,
            }));
        });
        expect(dnrPriorities).toEqual(
            expect.arrayContaining([
                { filter: '||testbench.com^', type: 'allow', priority: 21 },
                { filter: '||testbench.com^', type: 'modifyHeaders', priority: 22 },
                { filter: '||sub.testbench.com^', type: 'allow', priority: 31 },
                { filter: '||sub.testbench.com^', type: 'modifyHeaders', priority: 32 },
                { filter: '||deep.sub.testbench.com^', type: 'allow', priority: 43 },
                { filter: '||deep.sub.testbench.com^', type: 'modifyHeaders', priority: 44 },
            ])
        );

        // 6. Switching back to Domain mode on http://other.testbench.com:8123/ restores testbench.com as the active tab
        await optionsPanel.locator('#defaultscope').selectOption('domain');
        await testbench.bringToFront();
        await testbench.reload();
        await waitForPanelIdle(report);
        await expect(report.locator('#frames button.active')).toHaveAttribute('data-value', 'testbench.com');
        await expect(report.locator('#uncommit')).toBeEnabled();
        await expect(report.locator('#reset')).toBeEnabled();
    });

    test('Private Domains option (privatedomains): PSL private suffix bucketing and tenant isolation on github.io and s3.amazonaws.com', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await setOptions(serviceWorker, { defaultscope: 'domain', privatedomains: false });

        // 1. With privatedomains: false (default), navigate to http://sub.app1.github.io:8123/
        await testbench.goto('http://sub.app1.github.io:8123/');
        const report = await openPanel('report');

        // Top-level origin collapses across the PSL private suffix to github.io
        await expect(report.locator('#frames button.active')).toHaveAttribute('data-value', 'github.io');

        // Trigger blocked fetch requests to multi-tenant PSL private domains (s3.amazonaws.com & cloudfront.net)
        await testbench.evaluate(async () => {
            await Promise.allSettled([
                fetch('https://sub.mybucket.s3.amazonaws.com/probe.json'),
                fetch('https://d111.cloudfront.net/probe.json'),
            ]);
        });
        await expect(await getSourceCheckbox(report, 'https://*.amazonaws.com', 'connect-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report, 'https://*.cloudfront.net', 'connect-src').locator()).toHaveClass(/violation/);

        // 2. Enable Allow Private Domains (#privatedomains) in Options panel and reload
        const optionsPanel = await openPanel('options');
        await optionsPanel.locator('#privatedomains').check();
        await testbench.bringToFront();
        await testbench.reload();
        await waitForPanelIdle(report);

        // Top-level origin now buckets by tenant app1.github.io (collapsing sub.app1.github.io -> app1.github.io, NOT github.io!)
        await expect(report.locator('#frames button.active')).toHaveAttribute('data-value', 'app1.github.io');

        // Trigger the same blocked fetch to https://sub.mybucket.s3.amazonaws.com/probe.json:
        // s3.amazonaws.com is now treated as a PSL private suffix, so the registrable domain is mybucket.s3.amazonaws.com!
        await testbench.evaluate(async () => {
            await Promise.allSettled([fetch('https://sub.mybucket.s3.amazonaws.com/probe.json')]);
        });
        await expect(
            await getSourceCheckbox(report, 'https://*.mybucket.s3.amazonaws.com', 'connect-src').locator()
        ).toHaveClass(/violation/);

        // 3. Tenant isolation: a rule on app1.github.io (||app1.github.io^) does not affect app2.github.io
        await getSourceCheckbox(report, "'none'", 'connect-src').check();
        await testbench.reload();
        expect((await getOnloadBadges(testbench))['fetch-self']).toBe('Blocked');

        await testbench.goto('http://app2.github.io:8123/');
        await waitForPanelIdle(report);
        await expect(report.locator('#frames button.active')).toHaveAttribute('data-value', 'app2.github.io');
        expect((await getOnloadBadges(testbench))['fetch-self']).toBe('Allowed');
    });

    test('Untrusted web content and HTML/selector payloads render as inert text across panels', async ({
        context,
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        const errors = [];
        const onPageError = (err) => errors.push(String(err));
        const onPage = (page) => page.on('pageerror', onPageError);
        context.on('page', onPage);

        try {
        await setDefaultPolicy(serviceWorker, 1);

        // Deliver hostile HTML/script/selector payloads via Server CSP headers:
        // - passthrough directives rendered into textarea#servercsp
        // - invalid HTML-bearing tokens in img-src (must be rejected by isValidSource)
        // - a path-bearing source with HTML in its path (path stripped to https://example.com)
        // - sandbox tokens attempting DOM-ID clobbering (#commit, #reset, #sandbox-enabled)
        const hostileCsp = [
            `base-uri </textarea><img src=x onerror="window.__xss=1"> <svg onload="window.__xss=2">`,
            `<script>window.__xss=3</script> "][data-x="`,
            `img-src <img/src=x/onerror=window.__xss=4> 'nonce-<script>window.__xss=5</script>' https://example.com/<img/src=x>`,
            `sandbox commit reset sandbox-enabled allow-scripts`,
        ].join('; ');

        await testbench.goto(`http://127.0.0.1:8123/?csp=${encodeURIComponent(hostileCsp)}`);
        await getOnloadBadges(testbench);

        // Trigger a violation whose blocked-uri path/query contains HTML and selector metacharacters
        await testbench.evaluate(() => {
            fetch('https://api.github.com/<img%20src=x%20onerror=1>?"><svg>').catch(() => {});
        });

        const report = await openPanel('report');

        // Wait for both the server CSP and the violation to populate
        await expect(report.locator('#servercsp')).toContainText('</textarea><img src=x onerror="window.__xss=1">');
        await expect(report.locator('#servercsp')).toContainText('"][data-x="');
        await expect
            .poll(async () => (await getReportedViolations(report))['https://*.github.com'] ?? [])
            .toContain('connect-src');

        // Verify zero XSS execution and zero injected HTML elements in Report
        const reportAudit = await report.evaluate(() => ({
            xss: window.__xss ?? null,
            injectedMedia: document.querySelectorAll('img, svg').length,
            scripts: Array.from(document.querySelectorAll('script'), (s) => s.getAttribute('src')),
            serverSources: Array.from(document.querySelectorAll('#serversources tbody th'), (th) => th.title),
        }));
        expect(reportAudit.xss).toBeNull();
        expect(reportAudit.injectedMedia).toBe(0);
        expect(reportAudit.scripts.every((src) => src && !src.includes('__xss'))).toBe(true);
        // Invalid HTML tokens dropped; path-bearing source stripped cleanly to https://example.com
        expect(reportAudit.serverSources).toEqual(['https://example.com']);

        // Accept server policy and verify hostile sandbox tokens did not clobber unrelated DOM IDs
        await report.locator('#serverpolicy summary').click();
        await report.locator('#accept').click();
        await expect
            .poll(() =>
                serviceWorker.evaluate(async () => {
                    const rules = await chrome.declarativeNetRequest.getSessionRules();
                    const r = rules.find((x) => x.action.type === 'modifyHeaders' && x.condition.urlFilter === '||127.0.0.1^');
                    return r?.action.responseHeaders[0].value ?? '';
                })
            )
            .toContain('sandbox allow-scripts');

        const dnrValue = await serviceWorker.evaluate(async () => {
            const rules = await chrome.declarativeNetRequest.getSessionRules();
            const r = rules.find((x) => x.action.type === 'modifyHeaders' && x.condition.urlFilter === '||127.0.0.1^');
            return r.action.responseHeaders[0].value;
        });
        expect(dnrValue).not.toContain('commit');
        expect(dnrValue).not.toContain('reset');
        expect(dnrValue).not.toContain('sandbox-enabled');
        expect(dnrValue).not.toContain('<img');
        expect(dnrValue).not.toContain('<script');
        await expect(report.locator('#sandbox-enabled')).toBeChecked();
        await expect(report.locator('#allow-scripts')).toBeChecked();

        // Commit the session rule, then inspect Manage Rules and About panels
        await report.locator('#commit').click();
        await expect
            .poll(() =>
                serviceWorker.evaluate(async () => {
                    const rules = await chrome.declarativeNetRequest.getDynamicRules();
                    return rules.some((x) => x.action.type === 'modifyHeaders' && x.condition.urlFilter === '||127.0.0.1^');
                })
            )
            .toBe(true);

        const manage = await openPanel('manage');
        const manageAudit = await manage.evaluate(() => ({
            xss: window.__xss ?? null,
            injectedMedia: document.querySelectorAll('img, svg').length,
            dynamicRows: document.querySelectorAll('#dynamic tbody tr').length,
        }));
        expect(manageAudit.xss).toBeNull();
        expect(manageAudit.injectedMedia).toBe(0);
        expect(manageAudit.dynamicRows).toBe(1);

        const about = await openPanel('about');
        const aboutAudit = await about.evaluate(() => ({
            xss: window.__xss ?? null,
            injectedMedia: document.querySelectorAll('img, svg').length,
        }));
        expect(aboutAudit.xss).toBeNull();
        expect(aboutAudit.injectedMedia).toBe(0);

        // Create a Group whose name contains HTML and CSS selector metacharacters
        const hostileGroupName = `<img src=x onerror="window.__xss=7">"][data-x="`;
        const groupsPanel = await openPanel('groups');
        await groupsPanel.locator('#newname').fill(hostileGroupName);
        await groupsPanel.locator('#addgroup').click();

        const createdGroup = groupsPanel.locator('.group').filter({ hasText: hostileGroupName });
        await expect(createdGroup).toHaveCount(1);
        await expect(createdGroup.locator('.group-name')).toHaveText(hostileGroupName);
        await createdGroup.locator('.neworigin').fill('https://cdn.example.com');
        await createdGroup.locator('.addorigin').click();
        await getSourceCheckbox(groupsPanel, 'https://cdn.example.com', 'img-src', 'table.sources').check();

        const groupsAudit = await groupsPanel.evaluate(() => ({
            xss: window.__xss ?? null,
            injectedMedia: document.querySelectorAll('img, svg').length,
        }));
        expect(groupsAudit.xss).toBeNull();
        expect(groupsAudit.injectedMedia).toBe(0);

        // Verify Report panel renders the hostile group name safely in #trustgroup and applies it
        await expect(report.locator('#trustgroup option')).toContainText([hostileGroupName]);
        await report.locator('#trustgroup').selectOption(hostileGroupName);
        await report.locator('#applygroup').click();
        await expect
            .poll(() =>
                serviceWorker.evaluate(async () => {
                    const rules = await chrome.declarativeNetRequest.getSessionRules();
                    const r = rules.find((x) => x.action.type === 'modifyHeaders' && x.condition.urlFilter === '||127.0.0.1^');
                    return r?.action.responseHeaders[0].value ?? '';
                })
            )
            .toContain('https://cdn.example.com');

        const finalReportAudit = await report.evaluate(() => ({
            xss: window.__xss ?? null,
            injectedMedia: document.querySelectorAll('img, svg').length,
        }));
        expect(finalReportAudit.xss).toBeNull();
        expect(finalReportAudit.injectedMedia).toBe(0);
        expect(errors).toEqual([]);
        } finally {
            context.off('page', onPage);
        }
    });

    test('IPv6 origins (http://[::1]:8123/): Report panel is active (not inert), tracks server CSP and violations, enforces ||[::1]^ dNR rules, and syncs rule:[::1]', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.goto("http://[::1]:8123/?csp=script-src%20'nonce-test-nonce'");

        const badges = await getOnloadBadges(testbench);
        expect(badges['fetch-self']).toBe('Allowed');
        expect(badges['fetch']).toBe('Blocked');

        const report = await openPanel('report');

        // 1. Report panel must not be inert on an IPv6 origin, and [::1] must be the active frame button
        await expect(report.locator('body')).not.toHaveClass(/\binert\b/);
        const originBtn = report.locator('#frames button[data-value="[::1]"]');
        await expect(originBtn).toBeVisible();
        await expect(originBtn).toHaveClass(/\bactive\b/);
        await expect(originBtn).toHaveAttribute('data-origin', 'http://[::1]:8123');

        // 2. Verify PSL IPv6 validation and RFC 5952 canonicalization (collapsing zero runs to ::, stripping leading zeros,
        //    IPv4-mapped hex vs dotted-quad, RFC 6874 %25 zone IDs, and CSP source validation)
        const pslResults = await report.evaluate(async () => {
            const psl = await import('/include/psl.js');
            const { default: Help } = await import('/include/help.js');
            const { default: Policy } = await import('/include/policy.js');
            return {
                loopback: await psl.getScopedDomain('[::1]'),
                expandedLoopback: await psl.getScopedDomain('[0:0:0:0:0:0:0:1]'),
                unspecifiedUrl: URL.parse('http://[::]:80')?.hostname ?? null,
                allZerosUrl: URL.parse('http://[0000:0000:0000:0000:0000:0000:0000:0000]:80')?.hostname ?? null,
                unspecified: psl.getHostname('[::]'),
                allZeros: psl.getHostname('[0000:0000:0000:0000:0000:0000:0000:0000]'),
                expanded: psl.getHostname('[2001:0DB8:0000:0000:0000:0000:0000:0001]'),
                singleZeroGroup: psl.getHostname('[2001:0db8:0:1:1:1:1:1]'),
                longestRunWins: psl.getHostname('[2001:db8:0:0:1:0:0:0]'),
                v4MappedFromUrl: await psl.getScopedDomain(new URL('http://[::ffff:127.0.0.1]:8123/').hostname),
                v4MappedRawDotted: psl.getHostname('[::ffff:127.0.0.1]'),
                zoneIdUrl: URL.parse('http://[fe80::1%25eth0]/')?.hostname ?? null,
                zoneIdPsl: psl.getHostname('[fe80::1%25eth0]'),
                doubleColon: psl.getHostname('[::1::1]'),
                onlyColons: psl.getHostname('[::::]'),
                tooLongGroup: psl.getHostname('[12345::1]'),
                empty: psl.getHostname('[]'),
                extraCloseBracket: psl.getHostname('[]]'),
                extraOpenBracket: psl.getHostname('[[]'),
                doubleBrackets: psl.getHostname('[[::1]]'),
                trailingJunk: psl.getHostname('[::1]foo'),
                ipv6WithPort: psl.getHostname('[::1]:8080'),
                ipv6WithPort80: psl.getHostname('[::1]:80'),
                ipv6TrailingColon: psl.getHostname('[::1]:'),
                unbracketed: psl.getHostname('::1'),
                bracketedDns: psl.getHostname('[example.com]'),
                bracketedFqdnJunk: psl.getHostname('[x.af.]ff0_A1['),
                bracketedIpv4: psl.getHostname('[127.0.0.1]'),
                colonInDns: psl.getHostname('Ebf:LuijDdDTlUYOrwAn'),
                colonBracket: psl.getHostname('aF1:['),
                dnsWithPort: psl.getHostname('example.com:8080'),
                dnsWithPort80: psl.getHostname('example.com:80'),
                dnsTrailingColon: psl.getHostname('f:'),
                leadingDotOnly: Help.isValidSource('https://.'),
                leadingDotTld: Help.isValidSource('https://.com'),
                leadingDotDomain: Help.isValidSource('https://.example.com'),
                doubleTrailingDot: psl.getHostname('example.com..'),
                numericDoubleDot: Help.isValidSource('https://8..'),
                bogusIpv4Octets: psl.getHostname('999.999.999.999'),
                fiveOctetNumeric: psl.getHostname('1.2.3.4.5'),
                numericTld: psl.getHostname('xf4.2'),
                nonsenseUrl: URL.parse('http://[]]/'),
                cspSourceValid: Help.isValidSource('http://[::1]:8123'),
                cspLeadingDotValid: Help.isValidSource('https://.example.com'),
                cspTrailingDotValid: Help.isValidSource('https://example.com.'),
                cspImportable: Policy.importableSource('http://[::1]:8123'),
            };
        });
        expect(pslResults).toEqual({
            loopback: '[::1]',
            expandedLoopback: '[::1]',
            unspecifiedUrl: '[::]',
            allZerosUrl: '[::]',
            unspecified: null,
            allZeros: null,
            expanded: '[2001:db8::1]',
            singleZeroGroup: '[2001:db8:0:1:1:1:1:1]',
            longestRunWins: '[2001:db8:0:0:1::]',
            v4MappedFromUrl: '[::ffff:7f00:1]',
            v4MappedRawDotted: '[::ffff:7f00:1]',
            zoneIdUrl: null,
            zoneIdPsl: null,
            doubleColon: null,
            onlyColons: null,
            tooLongGroup: null,
            empty: null,
            extraCloseBracket: null,
            extraOpenBracket: null,
            doubleBrackets: null,
            trailingJunk: null,
            ipv6WithPort: null,
            ipv6WithPort80: null,
            ipv6TrailingColon: null,
            unbracketed: null,
            bracketedDns: null,
            bracketedFqdnJunk: null,
            bracketedIpv4: null,
            colonInDns: null,
            colonBracket: null,
            dnsWithPort: null,
            dnsWithPort80: null,
            dnsTrailingColon: null,
            leadingDotOnly: false,
            leadingDotTld: false,
            leadingDotDomain: false,
            doubleTrailingDot: 'example.com',
            numericDoubleDot: false,
            bogusIpv4Octets: null,
            fiveOctetNumeric: null,
            numericTld: null,
            nonsenseUrl: null,
            cspSourceValid: false,
            cspLeadingDotValid: false,
            cspTrailingDotValid: false,
            cspImportable: null,
        });

        // 3. Server CSP on [::1] is captured and displayed
        await expect(report.locator('div#serverpolicy details')).toBeVisible();

        // 4. Page-load violations on [::1] are attributed to [::1]
        await expect.poll(() => getReportedViolations(report)).toEqual({
            'data:': ['media-src'],
            'https://*.github.com': ['connect-src'],
            'https://*.google.com': ['script-src', 'media-src'],
            'https://example.com': ['frame-src', 'manifest-src'],
        });

        // 5. Cross-origin IPv6 violation folds to scheme (http:) since CSP3 host-source grammar excludes IPv6 literals
        const crossIpv6Blocked = await testbench.evaluate(() =>
            fetch('http://[2001:db8::1]:8123/cookie-echo?cors=1').then(() => false, () => true)
        );
        expect(crossIpv6Blocked).toBe(true);
        await expect(await getSourceCheckbox(report, 'http:', 'connect-src').locator()).toHaveClass(/\bviolation\b/);

        // 6. Toggling checkboxes installs a session rule with urlFilter "||[::1]^" at L=1 priority (13, 14)
        await getSourceCheckbox(report, 'https://*.github.com', 'connect-src').check();
        await getSourceCheckbox(report, 'http:', 'connect-src').check();

        const sessionFilter = await serviceWorker.evaluate(async () => {
            const rules = await chrome.declarativeNetRequest.getSessionRules();
            return rules
                .filter((r) => r.condition.urlFilter === '||[::1]^')
                .map((r) => `${r.action.type}:${r.priority}`)
                .sort();
        });
        expect(sessionFilter).toEqual(['allow:13', 'modifyHeaders:14']);

        // Navigating to the uncollapsed form http://[0:0:0:0:0:0:0:1]:8123/ canonicalizes to [::1] and matches ||[::1]^
        await testbench.goto("http://[0:0:0:0:0:0:0:1]:8123/?csp=script-src%20'nonce-test-nonce'");
        const reloadedBadges = await getOnloadBadges(testbench);
        expect(reloadedBadges['fetch']).toBe('Allowed');
        await expect(report.locator('#frames button[data-value="[::1]"]')).toHaveClass(/\bactive\b/);

        const crossIpv6Allowed = await testbench.evaluate(() =>
            fetch('http://[2001:0db8:0000:0000:0000:0000:0000:0001]:8123/cookie-echo?cors=1').then((r) => r.ok, () => false)
        );
        expect(crossIpv6Allowed).toBe(true);

        // 7. Commit (promotes to dynamic L=1 priority 11, 12) and verify Cloud Sync Push/Pull preserves colons in rule:[::1]
        await report.locator('#commit').click();
        await expect
            .poll(() =>
                serviceWorker.evaluate(async () => {
                    const rules = await chrome.declarativeNetRequest.getDynamicRules();
                    return rules
                        .filter((r) => r.condition.urlFilter === '||[::1]^')
                        .map((r) => `${r.action.type}:${r.priority}`)
                        .sort();
                })
            )
            .toEqual(['allow:11', 'modifyHeaders:12']);

        const syncRoundTrip = await report.evaluate(async () => {
            const { RulesManager } = await import('/include/sidepanel.js');
            await RulesManager.pushToCloud();
            const cloudHosts = await RulesManager.getCloudRules();
            await RulesManager.resetAllRules();
            await RulesManager.pullFromCloud();
            return {
                cloudHosts,
                restoredHosts: RulesManager.getRules().map((r) => r.host),
                lookupHost: RulesManager.getHostRule('[::1]')?.host ?? null,
            };
        });
        expect(syncRoundTrip).toEqual({
            cloudHosts: ['[::1]'],
            restoredHosts: ['[::1]'],
            lookupHost: '[::1]',
        });
    });
});
