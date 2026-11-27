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

test.describe('Extension Panels: Navigation, Rules, Groups, Options, Help, & About', () => {
    test('Panel switcher (#panel) navigates across all 7 panels', async ({ openPanel }) => {
        const panel = await openPanel('report');

        // When opened in a standalone tab, sidepanel.js adds body.standalone
        await expect(panel.locator('body')).toHaveClass(/\bstandalone\b/);

        const expectedPages = [
            { label: 'Report', path: '/panels/report.html', heading: 'Report' },
            { label: 'Rules', path: '/panels/manage.html', heading: 'Rules' },
            { label: 'Groups', path: '/panels/groups.html', heading: 'Groups' },
            { label: 'Options', path: '/panels/options.html', heading: 'Options' },
            { label: 'Export', path: '/panels/export.html', heading: 'Export' },
            { label: 'Help', path: '/panels/help.html', heading: 'Help' },
            { label: 'About', path: '/panels/about.html', heading: 'About' },
        ];

        const options = await panel.locator('#panel option').evaluateAll((opts) =>
            opts.map((o) => ({ label: o.innerText, value: o.value }))
        );
        expect(options).toEqual(expectedPages.map(({ label, path }) => ({ label, value: path })));

        for (const page of expectedPages.slice(1)) {
            await Promise.all([
                panel.waitForURL((url) => url.pathname === page.path),
                panel.locator('#panel').selectOption(page.path, { force: true }),
            ]);
            await expect(panel.locator('h1')).toHaveText(page.heading);
            await expect(panel.locator('#panel')).toHaveValue(page.path);
        }
    });

    test('Rules panel: session, dynamic, and static tables, filter, select all, invert, commit, uncommit, and remove', async ({
        openPanel,
    }) => {
        const report = await openPanel('report');
        // Create a session rule for 127.0.0.1
        await getSourceCheckbox(report, "'self'", 'script-src').check();
        await expect(report.locator('#commit')).toBeEnabled();

        const rulesPanel = await openPanel('manage');

        // Session table has 127.0.0.1, Dynamic table is empty, Static table has 6 rulesets (base + 5 modes)
        await expect(rulesPanel.locator('#session tr')).toHaveCount(1);
        await expect(rulesPanel.locator('#session tr').first()).toContainText('127.0.0.1');
        await expect(rulesPanel.locator('#dynamic tr')).toHaveCount(0);
        await expect(rulesPanel.locator('#static tr')).toHaveCount(6);

        // Verify directive icon spans are rendered on the session rule row
        await expect(rulesPanel.locator('#session tr .directive:not(.unused)').first()).toBeVisible();
        await expect(rulesPanel.locator('#session tr .directive:not(.unused)').first()).toHaveText('📜');

        // Filter hides non-matching rows and shows matching rows
        await rulesPanel.locator('#filter').fill('nonexistent-host');
        await expect(rulesPanel.locator('#session tr').first()).toBeHidden();
        await rulesPanel.locator('#filter').fill('127.0.0.1');
        await expect(rulesPanel.locator('#session tr').first()).toBeVisible();

        // Add a second session rule and verify Select All / Invert ignore filtered-out (hidden) rows
        await report.evaluate(async () => {
            const { RulesManager } = await import('/include/sidepanel.js');
            const { default: Policy } = await import('/include/policy.js');
            await RulesManager.addSessionRule('other.test', new Policy("img-src 'self'"));
        });
        await expect(rulesPanel.locator('#session tr')).toHaveCount(2);
        const row127 = rulesPanel.locator('#session tr').filter({ hasText: '127.0.0.1' });
        const rowOther = rulesPanel.locator('#session tr').filter({ hasText: 'other.test' });
        await expect(row127).toBeVisible();
        await expect(rowOther).toBeHidden();

        const sessionChk = row127.locator('input[type="checkbox"]');
        const otherChk = rowOther.locator('input[type="checkbox"]');
        await rulesPanel.locator('#selectsession').click();
        await expect(sessionChk).toBeChecked();
        await expect(otherChk).not.toBeChecked();

        await rulesPanel.locator('#invertsession').click();
        await expect(sessionChk).not.toBeChecked();
        await expect(otherChk).not.toBeChecked();

        // Filter to other.test and remove it, then clear the filter
        await rulesPanel.locator('#filter').fill('other.test');
        await expect(row127).toBeHidden();
        await expect(rowOther).toBeVisible();
        await rulesPanel.locator('#selectsession').click();
        await expect(otherChk).toBeChecked();
        await expect(sessionChk).not.toBeChecked();
        await rulesPanel.locator('#removesession').click();
        await expect(rulesPanel.locator('#session tr')).toHaveCount(1);
        await rulesPanel.locator('#filter').fill('');
        await expect(row127).toBeVisible();

        // Select All & Invert on Session Rules
        await expect(sessionChk).not.toBeChecked();
        await rulesPanel.locator('#selectsession').click();
        await expect(sessionChk).toBeChecked();
        await rulesPanel.locator('#invertsession').click();
        await expect(sessionChk).not.toBeChecked();
        await rulesPanel.locator('#invertsession').click();
        await expect(sessionChk).toBeChecked();

        // Commit moves rule from #session to #dynamic
        await rulesPanel.locator('#commit').click();
        await expect(rulesPanel.locator('#session tr')).toHaveCount(0);
        await expect(rulesPanel.locator('#dynamic tr')).toHaveCount(1);
        await expect(rulesPanel.locator('#dynamic tr').first()).toContainText('127.0.0.1');

        // Select All & Invert on Dynamic Rules
        const dynamicChk = rulesPanel.locator('#dynamic tr input[type="checkbox"]').first();
        await rulesPanel.locator('#selectdynamic').click();
        await expect(dynamicChk).toBeChecked();
        await rulesPanel.locator('#invertdynamic').click();
        await expect(dynamicChk).not.toBeChecked();
        await rulesPanel.locator('#selectdynamic').click();

        // Uncommit moves rule back from #dynamic to #session
        await rulesPanel.locator('#uncommit').click();
        await expect(rulesPanel.locator('#dynamic tr')).toHaveCount(0);
        await expect(rulesPanel.locator('#session tr')).toHaveCount(1);

        // Commit again, then Remove from #dynamic
        await rulesPanel.locator('#selectsession').click();
        await rulesPanel.locator('#commit').click();
        await expect(rulesPanel.locator('#dynamic tr')).toHaveCount(1);
        await rulesPanel.locator('#selectdynamic').click();
        await rulesPanel.locator('#removedynamic').click();
        await expect(rulesPanel.locator('#dynamic tr')).toHaveCount(0);

        // Recreate a session rule and Remove from #session
        await getSourceCheckbox(report, "'self'", 'img-src').check();
        await expect(rulesPanel.locator('#session tr')).toHaveCount(1);
        await rulesPanel.locator('#selectsession').click();
        await rulesPanel.locator('#removesession').click();
        await expect(rulesPanel.locator('#session tr')).toHaveCount(0);
    });

    test('Groups panel: create/delete group, add/remove origin, 3-state checkbox cycle, apply group in Report, and Ignore group', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        const groupsPanel = await openPanel('groups');

        // Built-in Ignore group exists and its delete button is hidden by CSS
        const ignoreGroup = groupsPanel.locator('section.group[data-name="Ignore"]');
        await expect(ignoreGroup).toBeVisible();
        await expect(ignoreGroup.locator('button.delgroup')).toBeHidden();

        // Create a new custom group "Analytics"
        await groupsPanel.locator('#newname').fill('Analytics');
        await groupsPanel.locator('#addgroup').click();
        const analyticsGroup = groupsPanel.locator('section.group[data-name="Analytics"]');
        await expect(analyticsGroup).toBeVisible();
        await expect(analyticsGroup.locator('button.delgroup')).toBeVisible();

        // Reject invalid source via HTML5 validity check
        const originInput = analyticsGroup.locator('input.neworigin');
        await originInput.fill('not a valid source!!!');
        await analyticsGroup.locator('button.addorigin').click();
        const isValid = await originInput.evaluate((el) => el.checkValidity());
        expect(isValid).toBe(false);
        await expect(analyticsGroup.locator('tbody tr')).toHaveCount(0);

        // Add two valid sources to Analytics
        await originInput.fill('https://www.google.com');
        await analyticsGroup.locator('button.addorigin').click();
        await expect(analyticsGroup.locator('tbody tr')).toHaveCount(1);

        await analyticsGroup.locator('input.neworigin').fill("'self'");
        await analyticsGroup.locator('button.addorigin').click();
        await expect(analyticsGroup.locator('tbody tr')).toHaveCount(2);

        // Test 3-state checkbox cycling: unchecked -> checked -> indeterminate (!dir) -> unchecked
        // Check img-src on https://www.google.com (1 click -> checked)
        const googleImgBox = await getSourceCheckbox(
            groupsPanel,
            'https://www.google.com',
            'img-src',
            'section.group[data-name="Analytics"] table.sources'
        ).locator();
        await googleImgBox.click();
        await expect(googleImgBox).toBeChecked();

        // Cycle script-src on 'self' twice (1st click -> checked, 2nd click -> indeterminate / !script-src)
        const selfScriptBox = await getSourceCheckbox(
            groupsPanel,
            "'self'",
            'script-src',
            'section.group[data-name="Analytics"] table.sources'
        ).locator();
        await selfScriptBox.click();
        await expect(selfScriptBox).toBeChecked();
        await selfScriptBox.click();
        await expect(selfScriptBox).not.toBeChecked();
        expect(await selfScriptBox.evaluate((el) => el.indeterminate)).toBe(true);

        // Cycle a 3rd time to verify it returns to unchecked + not indeterminate, then set back to indeterminate
        await selfScriptBox.click();
        await expect(selfScriptBox).not.toBeChecked();
        expect(await selfScriptBox.evaluate((el) => el.indeterminate)).toBe(false);
        await selfScriptBox.click();
        await selfScriptBox.click();
        expect(await selfScriptBox.evaluate((el) => el.indeterminate)).toBe(true);

        // Open Report panel and apply the "Analytics" group via #trustgroup + #applygroup
        const report = await openPanel('report');
        await expect(report.locator('#trustgroup option[value="Analytics"]')).toHaveCount(1);
        await report.locator('#trustgroup').selectOption('Analytics');
        await report.locator('#applygroup').click();
        await waitForPanelIdle(report);

        // Verify https://www.google.com img-src was checked and 'self' script-src was unchecked!
        await expect(await getSourceCheckbox(report, 'https://www.google.com', 'img-src').locator()).toBeChecked();
        await expect(await getSourceCheckbox(report, "'self'", 'script-src').locator()).not.toBeChecked();

        // Hover the https://www.google.com row to reveal button.delorigin, then remove it and delete the group
        await groupsPanel.bringToFront();
        const googleRow = analyticsGroup
            .locator('tbody tr')
            .filter({ has: groupsPanel.locator('th[title="https://www.google.com"]') });
        await googleRow.hover();
        await googleRow.locator('button.delorigin').click();
        await expect(analyticsGroup.locator('tbody tr')).toHaveCount(1);

        await analyticsGroup.locator('button.delgroup').click();
        await expect(analyticsGroup).toHaveCount(0);

        // Test Ignore group: add https://*.github.com with connect-src checked
        await ignoreGroup.locator('input.neworigin').fill('https://*.github.com');
        await ignoreGroup.locator('button.addorigin').click();
        const ignoreGithubConnect = await getSourceCheckbox(
            groupsPanel,
            'https://*.github.com',
            'connect-src',
            'section.group[data-name="Ignore"] table.sources'
        ).locator();
        await ignoreGithubConnect.click();
        await expect(ignoreGithubConnect).toBeChecked();

        // Re-open Report panel: https://*.github.com connect-src violation should now be suppressed
        const reportAfterIgnore = await openPanel('report');
        const violations = await getReportedViolations(reportAfterIgnore);
        expect(violations['https://*.github.com']).toBeUndefined();
    });

    test('Options panel: defaultpolicy slider, advanced toggle, badges, confirmactions, defaultscope, and privatedomains', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        const optionsPanel = await openPanel('options');
        const reportPanel = await openPanel('report');

        // 1. #advanced checkbox toggles body.show-advanced on panels (revealing advanced directive columns and source rows)
        const advancedSources = ["'unsafe-inline'", "'unsafe-eval'", "'wasm-unsafe-eval'", "'unsafe-hashes'", 'blob:'];
        await expect(reportPanel.locator('body')).not.toHaveClass(/\bshow-advanced\b/);
        for (const src of advancedSources) {
            await expect(reportPanel.locator(`table#sources tbody th[title="${src}"]`)).not.toBeVisible();
        }
        await optionsPanel.locator('#advanced').check();
        await expect(reportPanel.locator('body')).toHaveClass(/\bshow-advanced\b/);
        await expect(reportPanel.locator('table#sources th#child-src')).toBeVisible();
        for (const src of advancedSources) {
            await expect(reportPanel.locator(`table#sources tbody th[title="${src}"]`)).toBeVisible();
        }
        await optionsPanel.locator('#advanced').uncheck();
        await expect(reportPanel.locator('body')).not.toHaveClass(/\bshow-advanced\b/);
        for (const src of advancedSources) {
            await expect(reportPanel.locator(`table#sources tbody th[title="${src}"]`)).not.toBeVisible();
        }

        // 2. #defaultpolicy range slider updates enabled static rulesets
        await optionsPanel.locator('#defaultpolicy').fill('1');
        await optionsPanel.locator('#defaultpolicy').dispatchEvent('change');
        await expect
            .poll(async () =>
                serviceWorker.evaluate(() => chrome.declarativeNetRequest.getEnabledRulesets())
            )
            .toContain('firstparty');

        // 3. #badges option controls toolbar badge text ("!" on violation vs "")
        await reportPanel.close();
        await testbench.bringToFront();
        await testbench.reload();
        await expect
            .poll(async () => {
                const [tab] = await serviceWorker.evaluate(() =>
                    chrome.tabs.query({ active: true, currentWindow: true })
                );
                return serviceWorker.evaluate((tabId) => chrome.action.getBadgeText({ tabId }), tab.id);
            })
            .toBe('!');

        // Uncheck #badges and reload -> badge should remain empty ""
        await optionsPanel.locator('#badges').uncheck();
        await testbench.bringToFront();
        await testbench.reload();
        const badgeWhenDisabled = await serviceWorker.evaluate(async () => {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            return chrome.action.getBadgeText({ tabId: tab.id });
        });
        expect(badgeWhenDisabled).toBe('');

        // 4. #confirmactions gates destructive actions with window.confirm()
        await optionsPanel.locator('#confirmactions').check();
        const report = await openPanel('report');
        await getSourceCheckbox(report, "'self'", 'script-src').uncheck();
        await expect(report.locator('#abandon')).toBeEnabled();

        // Dismiss the confirm dialog -> session rule is NOT abandoned
        report.once('dialog', (dialog) => dialog.dismiss());
        await report.locator('#abandon').click();
        await expect(report.locator('#abandon')).toBeEnabled();

        // Accept the confirm dialog -> session rule IS abandoned
        report.once('dialog', (dialog) => dialog.accept());
        await report.locator('#abandon').click();
        await expect(report.locator('#abandon')).toBeDisabled();
        await optionsPanel.locator('#confirmactions').uncheck();

        // 5. #defaultscope ('domain' vs 'host') and #privatedomains (false vs true on github.io)
        const scopedDefault = await optionsPanel.evaluate(async () => {
            const psl = await import('/include/psl.js');
            return {
                subExample: await psl.getScopedDomain('sub.example.com'),
                githubIo: await psl.getScopedDomain('user.github.io'),
            };
        });
        expect(scopedDefault).toEqual({
            subExample: 'example.com',
            githubIo: 'github.io',
        });

        // Enable #privatedomains -> user.github.io becomes its own registrable domain
        await optionsPanel.locator('#privatedomains').check();
        const scopedPrivate = await optionsPanel.evaluate(async () => {
            const psl = await import('/include/psl.js');
            return {
                subUserGithubIo: await psl.getScopedDomain('sub.user.github.io'),
                userGithubIo: await psl.getScopedDomain('user.github.io'),
            };
        });
        expect(scopedPrivate).toEqual({
            subUserGithubIo: 'user.github.io',
            userGithubIo: 'user.github.io',
        });

        // Switch #defaultscope to 'host' -> sub.example.com stays 'sub.example.com'
        await optionsPanel.locator('#defaultscope').selectOption('host');
        const scopedHost = await optionsPanel.evaluate(async () => {
            const psl = await import('/include/psl.js');
            return psl.getScopedDomain('sub.example.com');
        });
        expect(scopedHost).toBe('sub.example.com');
    });

    test('Rapid changes to the Options slider leave one default preset enabled', async ({ serviceWorker, openPanel }) => {
        const panel = await openPanel('options');
        await waitForPanelIdle(panel);
        const slider = panel.locator('#defaultpolicy');
        const enabledPresets = () => serviceWorker.evaluate(async () =>
            (await chrome.declarativeNetRequest.getEnabledRulesets()).sort()
        );

        await expect(slider).toHaveValue('0');
        await expect.poll(enabledPresets).toEqual(['base', 'permissive']);

        await slider.focus();
        await panel.keyboard.press('ArrowRight');
        await panel.keyboard.press('End');

        await expect(slider).toHaveValue('4');
        await expect.poll(enabledPresets).toEqual(['base', 'strict']);
    });

    test('Concurrent rule edits from multiple panels do not collide on rule IDs', async ({ serviceWorker, testbench, openPanel }) => {
        const reportA = await openPanel('report');
        const reportB = await openPanel('report');
        const manage = await openPanel('manage');
        const panels = [reportA, reportB, manage];

        const panelHosts = (page) => page.evaluate(async () => {
            const { RulesManager } = await import('/include/sidepanel.js');
            return RulesManager.getRules().map((r) => `${r.isSession ? 'session' : 'dynamic'}:${r.host}`).sort();
        });
        const liveRules = () => serviceWorker.evaluate(async () => {
            const [session, dynamic] = await Promise.all([
                chrome.declarativeNetRequest.getSessionRules(),
                chrome.declarativeNetRequest.getDynamicRules(),
            ]);
            const summarize = (rules, kind) => rules
                .filter((r) => r.action.type === 'modifyHeaders' && r.condition.urlFilter)
                .map((r) => [
                    `${kind}:${r.condition.urlFilter.slice(2, -1)}`,
                    r.action.responseHeaders[0].value,
                ]);
            return [...summarize(session, 'session'), ...summarize(dynamic, 'dynamic')]
                .sort(([a], [b]) => a.localeCompare(b));
        });

        // Seed a session rule for c.test and wait until every panel's mirror has picked it up.
        await reportA.evaluate(async () => {
            const { RulesManager } = await import('/include/sidepanel.js');
            const { default: Policy } = await import('/include/policy.js');
            await RulesManager.addSessionRule('c.test', new Policy("img-src 'self'"));
        });
        for (const page of panels) {
            await expect.poll(() => panelHosts(page)).toEqual(['session:c.test']);
        }

        // Each panel mutates rules at the same moment, starting from the same synced mirror.
        const attempt = (page, fn, arg) => page.evaluate(async ({ fn, arg }) => {
            const { RulesManager } = await import('/include/sidepanel.js');
            const { default: Policy } = await import('/include/policy.js');
            try {
                if (fn === 'add') await RulesManager.addSessionRule(arg, new Policy("script-src 'self'"));
                if (fn === 'commit') await RulesManager.commitSessionRulesForHost(arg);
                return 'ok';
            } catch (e) {
                return String(e?.message ?? e);
            }
        }, { fn, arg });

        const results = await Promise.all([
            attempt(reportA, 'add', 'a.test'),
            attempt(reportB, 'add', 'b.test'),
            attempt(manage, 'commit', 'c.test'),
        ]);

        expect(results).toEqual(['ok', 'ok', 'ok']);

        // Immediately pushToCloud() from reportA (before NOTIFY_RULES necessarily arrives from manage's commit)
        // and verify #exclusive resynced reportA's mirror so c.test is pushed to cloud.
        const pushedCount = await reportA.evaluate(async () => {
            const { RulesManager } = await import('/include/sidepanel.js');
            return RulesManager.pushToCloud();
        });
        expect(pushedCount).toBe(1);
        const cloudRules = await reportB.evaluate(async () => {
            const { RulesManager } = await import('/include/sidepanel.js');
            return RulesManager.getCloudRules();
        });
        expect(cloudRules).toEqual(['c.test']);

        const expected = ['dynamic:c.test', 'session:a.test', 'session:b.test'];
        expect(await liveRules()).toEqual([
            ['dynamic:c.test', expect.stringContaining("img-src 'self'")],
            ['session:a.test', expect.stringContaining("script-src 'self'")],
            ['session:b.test', expect.stringContaining("script-src 'self'")],
        ]);

        // Every panel's mirror must converge on the live dNR state.
        for (const page of panels) {
            await expect.poll(() => panelHosts(page)).toEqual(expected);
        }
    });

    test('Help and About panels: example tables, version, and live rule statistics', async ({
        openPanel,
    }) => {
        // 1. Help panel populates all <table class="sources"> from #example-template
        const helpPanel = await openPanel('help');
        await helpPanel.evaluate(() => {
            document.querySelectorAll('details').forEach((d) => {
                d.open = true;
            });
        });
        const exampleTables = helpPanel.locator('table.sources');
        expect(await exampleTables.count()).toBeGreaterThanOrEqual(3);
        await expect(exampleTables.first().locator('tbody tr').first()).toBeVisible();
        await expect(helpPanel.locator('table.sources input.violation').first()).toBeVisible();

        // 2. About panel displays version and updates stats when rules change
        const aboutPanel = await openPanel('about');
        await expect(aboutPanel.locator('#version')).toContainText(/^v\d+\.\d+/);
        await expect(aboutPanel.locator('#stats')).toHaveText('0 session rules, 0 dynamic rules.');

        // Create a session rule in Report and verify About panel updates live via NOTIFY_RULES
        const report = await openPanel('report');
        await getSourceCheckbox(report, "'self'", 'connect-src').check();

        await expect(aboutPanel.locator('#stats')).toHaveText('1 session rules, 0 dynamic rules.');
        await expect(aboutPanel.locator('#topdirectives tbody tr').first()).toContainText('connect-src');
        await expect(aboutPanel.locator('#topsources tbody tr')).toContainText(["'self'"]);

        // Commit the rule and verify About panel updates to 0 session, 1 dynamic
        await report.locator('#commit').click();
        await expect(aboutPanel.locator('#stats')).toHaveText('0 session rules, 1 dynamic rules.');
    });

    test('Ignore group default-src + !directive negation gates badge & Report UI, and applyTrustGroup enforces none-mutex', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);

        // 1. Configure Ignore['https://*.github.com'] = ['default-src', '!script-src'] via Groups panel UI
        const groupsPanel = await openPanel('groups');
        const ignoreSection = groupsPanel.locator('.group[data-name="Ignore"]');
        await ignoreSection.locator('.neworigin').fill('https://*.github.com');
        await ignoreSection.locator('.addorigin').click();

        const defaultBox = await getSourceCheckbox(
            groupsPanel,
            'https://*.github.com',
            'default-src',
            '.group[data-name="Ignore"] table.sources'
        ).locator();
        const scriptBox = await getSourceCheckbox(
            groupsPanel,
            'https://*.github.com',
            'script-src',
            '.group[data-name="Ignore"] table.sources'
        ).locator();

        // Click default-src once (checked = ignore all directives by default)
        await defaultBox.click();
        await expect(defaultBox).toBeChecked();
        await expect(defaultBox).toHaveAttribute('title', /be IGNORED/);

        // Click script-src twice (checked -> indeterminate = !script-src override)
        await scriptBox.click();
        await scriptBox.click();
        expect(await scriptBox.evaluate((el) => ({ checked: el.checked, indeterminate: el.indeterminate }))).toEqual({
            checked: false,
            indeterminate: true,
        });
        await expect(scriptBox).toHaveAttribute('title', /be REPORTED/);

        // Wait for service worker's Options cache to see the updated Ignore group
        await expect
            .poll(() =>
                serviceWorker.evaluate(async () => {
                    const { groups } = await chrome.storage.local.get('groups');
                    return groups?.Ignore?.['https://*.github.com'];
                })
            )
            .toEqual(['default-src', '!script-src']);

        // 2. Navigate to /frame.html (no onload cross-origin probes -> clean tab, empty badge)
        await testbench.goto('http://127.0.0.1:8123/frame.html');
        const tabId = await groupsPanel.evaluate(async () => {
            const sidepanel = await import('/include/sidepanel.js');
            return (await sidepanel.getActiveTab()).id;
        });

        const getBadge = () =>
            serviceWorker.evaluate((id) => chrome.action.getBadgeText({ tabId: id }), tabId);
        const getTrackedViolations = () =>
            groupsPanel.evaluate(async (id) => {
                const { MessageTypes } = await import('/include/commands.js');
                return chrome.runtime.sendMessage({
                    command: MessageTypes.REQ_POLICY,
                    data: { id, domain: '127.0.0.1' },
                });
            }, tabId);

        expect(await getBadge()).toBe('');

        // 3. Trigger a connect-src violation for api.github.com (ignored via default-src):
        //    tracker must still record it in REQ_POLICY, while badge stays empty!
        await testbench.evaluate(() => {
            fetch('https://api.github.com/ignored-probe').catch(() => {});
        });
        await expect
            .poll(async () => (await getTrackedViolations())?.['connect-src'] ?? [])
            .toContain('https://*.github.com');
        expect(await getBadge()).toBe('');

        // 4. Trigger a script-src-elem violation for api.github.com (collapsed to script-src, negated by !script-src):
        //    badge MUST flip to "!"!
        await testbench.evaluate(() => {
            const s = document.createElement('script');
            s.src = 'https://api.github.com/negated-probe.js';
            document.head.appendChild(s);
        });
        await expect.poll(getBadge).toBe('!');

        // 5. Opening Report clears the badge and shows only the non-ignored script-src violation
        const report = await openPanel('report');
        await expect.poll(getBadge).toBe('');
        const reported = await getReportedViolations(report);
        expect(reported['https://*.github.com']).toEqual(['script-src']);

        // #trustcontrol must be hidden while only the built-in Ignore group exists
        await expect(report.locator('#trustcontrol')).not.toBeVisible();

        // 6. Add a custom group testing 'none'-leader mutex in both directions when applied over First Party mode:
        //    - First Party has img-src 'self' https: data: blob: -> group sets 'none' (must clear the rest)
        //    - First Party has worker-src 'none' -> group sets 'self' (must clear 'none')
        await groupsPanel.evaluate(async () => {
            const { default: Options } = await import('/include/options.js');
            const groups = await Options.getGroups();
            groups.MutexGroup = {
                "'none'": ['img-src'],
                "'self'": ['worker-src'],
            };
            await Options.saveGroups();
        });

        await expect(report.locator('#trustcontrol')).toBeVisible();
        const groupOptions = await report.locator('#trustgroup option').allTextContents();
        expect(groupOptions).toEqual(['MutexGroup']); // Ignore excluded

        await report.locator('#trustgroup').selectOption('MutexGroup');
        await report.locator('#applygroup').click();

        await expect
            .poll(() =>
                serviceWorker.evaluate(async () => {
                    const rules = await chrome.declarativeNetRequest.getSessionRules();
                    const r = rules.find((x) => x.action.type === 'modifyHeaders' && x.condition.urlFilter === '||127.0.0.1^');
                    return r?.action.responseHeaders[0].value ?? '';
                })
            )
            .toContain("worker-src 'self';");

        const finalHeader = await serviceWorker.evaluate(async () => {
            const rules = await chrome.declarativeNetRequest.getSessionRules();
            const r = rules.find((x) => x.action.type === 'modifyHeaders' && x.condition.urlFilter === '||127.0.0.1^');
            return r.action.responseHeaders[0].value;
        });
        expect(finalHeader).toMatch(/(?:^|; )img-src 'none';/);
        expect(finalHeader).toMatch(/(?:^|; )worker-src 'self';/);
    });
});
