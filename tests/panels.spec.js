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

test.describe('Extension Panels, Buttons, and Options', () => {
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

    test('Report panel: multi-origin frame tabs (#frames), many-frames, protected origin inert state, and dirty server table preservation', async ({
        serviceWorker,
        testbench,
        openPanel,
        extensionId,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        // Allow frame-src 'self' and https://example.com so the cross-origin iframe commits an active document
        const report = await openPanel('report');
        await getSourceCheckbox(report, "'self'", 'frame-src').check();
        await getSourceCheckbox(report, 'https://example.com', 'frame-src').check();
        await testbench.reload();

        // Both 127.0.0.1 and example.com should appear in div#frames
        await expect(report.locator('#frames button[data-value="127.0.0.1"]')).toBeVisible();
        await expect(report.locator('#frames button[data-value="example.com"]')).toBeVisible();

        // Switch to example.com tab and toggle a rule specifically for example.com
        await report.locator('#frames button[data-value="example.com"]').click();
        await waitForPanelIdle(report);
        await expect(report.locator('#frames button[data-value="example.com"]')).toHaveClass(/active/);

        await getSourceCheckbox(report, "'self'", 'script-src').uncheck();
        await expect(report.locator('#commit')).toBeEnabled();

        // Switch back to 127.0.0.1, allow http: in frame-src, and spawn 10 cross-origin frames via #many-frames-btn
        await report.locator('#frames button[data-value="127.0.0.1"]').click();
        await waitForPanelIdle(report);
        await getSourceCheckbox(report, 'http:', 'frame-src').check();
        await testbench.reload();
        await testbench.locator('#many-frames-btn').click();
        await expect(testbench.locator('#badge-special')).toHaveText('10 Frames Created', { timeout: 5000 });
        await expect(report.locator('#frames button[data-value="fake1.localhost"]')).toBeVisible();
        await expect(report.locator('#frames button[data-value$=".localhost"]')).toHaveCount(10);

        // Verify serverTable.dataset.dirty preserves user edits in #serversources across NOTIFY_UPDATE
        await testbench.locator('#csp').fill("script-src 'nonce-test-nonce' https://example.com");
        await testbench.locator('form.csp-form button[type="submit"]').click();
        const details = report.locator('div#serverpolicy details');
        await expect(details).toBeVisible();
        await details.locator('summary').click();
        await expect(report.locator('table#serversources tbody tr')).toHaveCount(2);
        const srvExScript = await getSourceCheckbox(
            report,
            'https://example.com',
            'script-src',
            'table#serversources'
        ).locator();
        await expect(srvExScript).toBeChecked();
        await srvExScript.uncheck();
        await expect(report.locator('table#serversources')).toHaveAttribute('data-dirty', 'true');

        // Trigger a new violation on testbench (which sends NOTIFY_UPDATE to report)
        await testbench.locator('#ws-page-btn').click();
        await expect(await getSourceCheckbox(report, 'wss://*.websocket.org', 'connect-src').locator()).toHaveClass(
            /violation/
        );
        // The user's uncheck in #serversources must not be clobbered by NOTIFY_UPDATE
        await expect(srvExScript).not.toBeChecked();

        // Navigate the active tab to a protected chrome-extension:// URL and verify body.inert
        await testbench.goto(`chrome-extension://${extensionId}/panels/about.html`);
        await expect(report.locator('body')).toHaveClass(/\binert\b/);
    });

    test('Report panel top-bar buttons (#commit, #uncommit, #abandon, #disable, #resume, Shift+#reload) and subdomain priority', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();

        const report = await openPanel('report');

        // Initially no session or dynamic rule exists for 127.0.0.1
        await expect(report.locator('#commit')).toBeDisabled();
        await expect(report.locator('#abandon')).toBeDisabled();
        await expect(report.locator('#uncommit')).toBeDisabled();
        await expect(report.locator('#reset')).toBeDisabled();
        await expect(report.locator('#resume')).toBeDisabled();

        // 1. Check a cell to create a session rule: #commit, #abandon, #reset enable
        const exConnect = getSourceCheckbox(report, 'https://example.com', 'connect-src');
        await exConnect.check();
        await expect(report.locator('#commit')).toBeEnabled();
        await expect(report.locator('#abandon')).toBeEnabled();
        await expect(report.locator('#uncommit')).toBeDisabled();
        await expect(report.locator('#reset')).toBeEnabled();

        // 2. Click #commit in Report panel: promotes session rule to dynamic
        await report.locator('#commit').click();
        await waitForPanelIdle(report);
        await expect(await exConnect.locator()).toHaveClass(/\bdynamic\b/);
        await expect(report.locator('#commit')).toBeDisabled();
        await expect(report.locator('#abandon')).toBeDisabled();
        await expect(report.locator('#uncommit')).toBeEnabled();
        await expect(report.locator('#reset')).toBeEnabled();

        // 3. Make a session draft edit on top of the dynamic rule, then click #abandon to revert
        await exConnect.uncheck();
        await expect(await exConnect.locator()).not.toBeChecked();
        await expect(report.locator('#commit')).toBeEnabled();
        await expect(report.locator('#abandon')).toBeEnabled();
        await expect(report.locator('#uncommit')).toBeDisabled();

        await report.locator('#abandon').click();
        await waitForPanelIdle(report);
        await expect(await exConnect.locator()).toBeChecked();
        await expect(await exConnect.locator()).toHaveClass(/\bdynamic\b/);
        await expect(report.locator('#commit')).toBeDisabled();
        await expect(report.locator('#abandon')).toBeDisabled();
        await expect(report.locator('#uncommit')).toBeEnabled();

        // 4. Click #uncommit in Report panel: demotes dynamic rule back to session
        await report.locator('#uncommit').click();
        await waitForPanelIdle(report);
        await expect(await exConnect.locator()).toHaveClass(/\bsession\b/);
        await expect(report.locator('#commit')).toBeEnabled();
        await expect(report.locator('#abandon')).toBeEnabled();
        await expect(report.locator('#uncommit')).toBeDisabled();

        // Clean up host rules via #reset
        await report.locator('#reset').click();
        await waitForPanelIdle(report);
        await expect(report.locator('#reset')).toBeDisabled();

        // 5. #disable and #resume in Strict mode (4): bypasses CSP on the active tab
        await setDefaultPolicy(serviceWorker, 4);
        await testbench.reload();
        await expect(testbench.locator('#onload-summary')).toHaveText('23 Probes');

        await report.locator('#disable').click();
        await waitForPanelIdle(report);
        await expect(report.locator('#resume')).toBeEnabled();
        await expect(report.locator('#disable')).toBeHidden();

        // Shift+Click #reload (bypassCache: true) and verify all 21 probes are Allowed while exempt
        await Promise.all([
            testbench.waitForNavigation(),
            report.locator('#reload').click({ modifiers: ['Shift'] }),
        ]);
        const badges = await getOnloadBadges(testbench);
        for (const [probe, status] of Object.entries(badges)) {
            expect(status, `probe ${probe} should be Allowed while tab is exempt`).toBe('Allowed');
        }

        // Click #resume and reload: Strict mode blocks scripts and subresources again
        await report.locator('#resume').click();
        await waitForPanelIdle(report);
        await expect(report.locator('#resume')).toBeDisabled();
        await expect(report.locator('#disable')).toBeVisible();

        await Promise.all([
            testbench.waitForNavigation(),
            report.locator('#reload').click(),
        ]);
        await expect(testbench.locator('#onload-summary')).toHaveText('23 Probes');
    });

    test('A session rule replaces (does not intersect with) the dynamic rule for the same host, and Abandon restores it', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();
        const report = await openPanel('report');

        const selfConnect = getSourceCheckbox(report, "'self'", 'connect-src');
        const noneConnect = getSourceCheckbox(report, "'none'", 'connect-src');
        const githubConnect = getSourceCheckbox(report, 'https://*.github.com', 'connect-src');

        // Reload the testbench and read the two connect-src probes:
        // fetch-self = fetch('/dot.png'), fetch = fetch('https://api.github.com/').
        const reloadAndProbe = async () => {
            await testbench.reload();
            const badges = await getOnloadBadges(testbench);
            await waitForPanelIdle(report);
            return { fetchSelf: badges['fetch-self'], fetch: badges['fetch'] };
        };
        const hostRulePriorities = () => serviceWorker.evaluate(async () => {
            const pick = (rules) => rules
                .filter((r) => r.condition.urlFilter === '||127.0.0.1^')
                .map((r) => `${r.action.type}:${r.priority}`)
                .sort();
            return {
                session: pick(await chrome.declarativeNetRequest.getSessionRules()),
                dynamic: pick(await chrome.declarativeNetRequest.getDynamicRules()),
            };
        });

        try {
            // #commit and #abandon run in the body click handler, outside the "report" lock, so
            // waitForPanelIdle() can return before the dNR update lands; poll dNR instead.
            const kDynamicPair = ['allow:41', 'modifyHeaders:42'];
            const kSessionPair = ['allow:43', 'modifyHeaders:44'];
            const clickAndWait = async (button, expected) => {
                await report.locator(button).click();
                await expect.poll(hostRulePriorities).toEqual(expected);
                await waitForPanelIdle(report);
            };

            // Baseline (firstparty static default): connect-src 'self'.
            expect(await reloadAndProbe()).toEqual({ fetchSelf: 'Allowed', fetch: 'Blocked' });

            // 1. Dynamic rule that blocks everything: connect-src 'none', committed.
            await noneConnect.check();
            await clickAndWait('#commit', { session: [], dynamic: kDynamicPair });
            expect(await reloadAndProbe()).toEqual({ fetchSelf: 'Blocked', fetch: 'Blocked' });

            // 2. Looser session draft on top: connect-src 'self' https://*.github.com.
            //    If the browser enforced both policies (intersection), everything would stay blocked;
            //    the session rule's allow override must suppress the same host's dynamic append.
            //    127.0.0.1 has 4 labels: dynamic pair at 10*4 + 1..2, session pair at 10*4 + 3..4.
            await githubConnect.check();
            await selfConnect.check();
            await expect(await noneConnect.locator()).not.toBeChecked();
            expect(await hostRulePriorities()).toEqual({ session: kSessionPair, dynamic: kDynamicPair });
            expect(await reloadAndProbe()).toEqual({ fetchSelf: 'Allowed', fetch: 'Allowed' });

            // 3. Abandon drops the session pair, so the dynamic 'none' rule is enforced again.
            await clickAndWait('#abandon', { session: [], dynamic: kDynamicPair });
            await expect(await noneConnect.locator()).toBeChecked();
            expect(await reloadAndProbe()).toEqual({ fetchSelf: 'Blocked', fetch: 'Blocked' });

            // 4. The reverse: a stricter session draft over a looser dynamic rule.
            await githubConnect.check();
            await selfConnect.check();
            await clickAndWait('#commit', { session: [], dynamic: kDynamicPair });
            expect(await reloadAndProbe()).toEqual({ fetchSelf: 'Allowed', fetch: 'Allowed' });

            await githubConnect.uncheck();
            expect(await hostRulePriorities()).toEqual({ session: kSessionPair, dynamic: kDynamicPair });
            expect(await reloadAndProbe()).toEqual({ fetchSelf: 'Allowed', fetch: 'Blocked' });

            await clickAndWait('#abandon', { session: [], dynamic: kDynamicPair });
            expect(await reloadAndProbe()).toEqual({ fetchSelf: 'Allowed', fetch: 'Allowed' });
        } finally {
            await report.locator('#reset').click();
            await waitForPanelIdle(report);
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
        await rulesPanel.locator('#filter').fill('');

        // Select All & Invert on Session Rules
        const sessionChk = rulesPanel.locator('#session tr input[type="checkbox"]').first();
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

    test('Export & Sync panel: JSON export/save, validation alerts, file import, download, and cloud Push/Pull', async ({
        openPanel,
    }) => {
        const report = await openPanel('report');
        // Create and commit a rule for 127.0.0.1 so we have a dynamic rule to export/sync
        await getSourceCheckbox(report, "'self'", 'script-src').check();
        await report.locator('#commit').click();
        await expect(report.locator('#uncommit')).toBeEnabled();

        const exportPanel = await openPanel('export');
        await expect(exportPanel.locator('#export')).not.toHaveValue('');

        const initialBlob = JSON.parse(await exportPanel.locator('#export').inputValue());
        expect(initialBlob.dynamic).toHaveLength(1);
        expect(initialBlob.options.defaultscope).toBe('domain');

        // 1. Test invalid JSON alert on #save
        let dialogMsg = '';
        exportPanel.once('dialog', async (d) => {
            dialogMsg = d.message();
            await d.accept();
        });
        await exportPanel.locator('#export').fill('{ invalid json ');
        await exportPanel.locator('#save').click();
        expect(dialogMsg).toContain('Invalid JSON');

        // 2. Test invalid backup format alert on #save
        dialogMsg = '';
        exportPanel.once('dialog', async (d) => {
            dialogMsg = d.message();
            await d.accept();
        });
        await exportPanel.locator('#export').fill('{"options": {"defaultpolicy": "bad"}}');
        await exportPanel.locator('#save').click();
        expect(dialogMsg).toContain('Invalid backup format');

        // 3. Test valid JSON edit + #save
        const modifiedBlob = structuredClone(initialBlob);
        modifiedBlob.options.advanced = true;
        modifiedBlob.groups.CustomSavedGroup = { 'https://example.com': ['img-src'] };
        modifiedBlob.groups.TempGroup = { 'https://temp.example.com': ['script-src'] };
        await exportPanel.locator('#export').fill(JSON.stringify(modifiedBlob));
        await exportPanel.locator('#save').click();
        await expect(exportPanel.locator('body')).toHaveClass(/\bshow-advanced\b/);

        // 4. Test #import via file input (and verify deleted groups/origins are removed)
        const importedBlob = structuredClone(modifiedBlob);
        importedBlob.options.advanced = false;
        delete importedBlob.groups.TempGroup;
        importedBlob.groups.CustomSavedGroup = { 'https://cdn.example.com': ['img-src'] };
        await exportPanel.locator('#file').setInputFiles({
            name: 'backup.json',
            mimeType: 'application/json',
            buffer: Buffer.from(JSON.stringify(importedBlob)),
        });
        await expect(exportPanel.locator('body')).not.toHaveClass(/\bshow-advanced\b/);
        const afterImportBlob = JSON.parse(await exportPanel.locator('#export').inputValue());
        expect(afterImportBlob.groups).toEqual({
            Ignore: {},
            CustomSavedGroup: { 'https://cdn.example.com': ['img-src'] },
        });

        // 5. Test #download triggers a matrix3.json download
        const [download] = await Promise.all([
            exportPanel.waitForEvent('download'),
            exportPanel.locator('#download').click(),
        ]);
        expect(download.suggestedFilename()).toBe('matrix3.json');

        // 6. Test Cloud Sync (#push and #pull)
        await expect(exportPanel.locator('#lastpush')).toHaveText('');
        await exportPanel.locator('#push').click();
        await expect(exportPanel.locator('#lastpush')).toContainText('Last cloud push: 1 rules, 2 groups');

        // Delete local dynamic rule via Report Reset, then Pull from cloud to restore it
        await report.locator('#reset').click();
        await expect(report.locator('#reset')).toBeDisabled();

        await exportPanel.locator('#pull').click();
        await expect
            .poll(async () => JSON.parse(await exportPanel.locator('#export').inputValue()).dynamic.length)
            .toBe(1);
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
        const liveHosts = () => serviceWorker.evaluate(async () => {
            const [session, dynamic] = await Promise.all([
                chrome.declarativeNetRequest.getSessionRules(),
                chrome.declarativeNetRequest.getDynamicRules(),
            ]);
            const hosts = (rules, kind) => rules
                .filter((r) => r.action.type === 'modifyHeaders' && r.condition.urlFilter)
                .map((r) => `${kind}:${r.condition.urlFilter.slice(2, -1)}`);
            return [...hosts(session, 'session'), ...hosts(dynamic, 'dynamic')].sort();
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

        const expected = ['dynamic:c.test', 'session:a.test', 'session:b.test'];
        expect(await liveHosts()).toEqual(expected);

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

    test('Multiple open tabs (same & different origins) and multiple open sidepanels sync rules, violations, groups, and Ignore exclusions live', async ({
        browserContext,
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);

        // Open 3 website tabs across 2 origins (127.0.0.1 and localhost):
        // - tab1 (testbench): http://127.0.0.1:8123/?csp=base-uri%20'self'
        // - tab2: http://localhost:8123/?csp=form-action%20'none' (different origin)
        // - tab3: http://127.0.0.1:8123/?csp=base-uri%20'self' (same origin as tab1)
        const tab1 = testbench;
        await tab1.goto("http://127.0.0.1:8123/?csp=base-uri%20'self'");

        const tab2 = await browserContext.newPage();
        await tab2.goto("http://localhost:8123/?csp=form-action%20'none'");

        const tab3 = await browserContext.newPage();
        await tab3.goto("http://127.0.0.1:8123/?csp=base-uri%20'self'");

        // Open 5 sidepanels simultaneously (including two Report panels!)
        const report1 = await openPanel('report');
        const report2 = await openPanel('report');
        const rulesPanel = await openPanel('manage');
        const groupsPanel = await openPanel('groups');
        const exportPanel = await openPanel('export');
        const aboutPanel = await openPanel('about');

        // 1. Active tab switching (chrome.tabs.onActivated) updates both Report panels
        await tab1.bringToFront();
        await expect(report1.locator('#frames button.active')).toHaveAttribute('data-value', '127.0.0.1');
        await expect(report2.locator('#frames button.active')).toHaveAttribute('data-value', '127.0.0.1');
        await expect(report1.locator('textarea#servercsp')).toHaveText("base-uri 'self';");
        await expect(report2.locator('textarea#servercsp')).toHaveText("base-uri 'self';");

        await tab2.bringToFront();
        await expect(report1.locator('#frames button.active')).toHaveAttribute('data-value', 'localhost');
        await expect(report2.locator('#frames button.active')).toHaveAttribute('data-value', 'localhost');
        await expect(report1.locator('textarea#servercsp')).toHaveText("form-action 'none';");
        await expect(report2.locator('textarea#servercsp')).toHaveText("form-action 'none';");

        // 2. Editing a rule for localhost in report1 syncs live to report2, rulesPanel, exportPanel, and aboutPanel
        await getSourceCheckbox(report1, 'https://example.com', 'script-src').check();
        await expect(await getSourceCheckbox(report2, 'https://example.com', 'script-src').locator()).toBeChecked();
        await expect(report2.locator('#commit')).toBeEnabled();
        await expect(rulesPanel.locator('#session tr')).toHaveCount(1);
        await expect(rulesPanel.locator('#session tr').first()).toContainText('localhost');
        await expect(aboutPanel.locator('#stats')).toHaveText('1 session rules, 0 dynamic rules.');
        await expect
            .poll(async () => JSON.parse(await exportPanel.locator('#export').inputValue()).session.length)
            .toBe(1);

        // Committing the localhost rule in rulesPanel syncs back to both report1 and report2
        await rulesPanel.locator('#selectsession').click();
        await rulesPanel.locator('#commit').click();
        await expect(report1.locator('#uncommit')).toBeEnabled();
        await expect(report2.locator('#uncommit')).toBeEnabled();
        await expect(await getSourceCheckbox(report1, 'https://example.com', 'script-src').locator()).toHaveClass(/\bdynamic\b/);
        await expect(await getSourceCheckbox(report2, 'https://example.com', 'script-src').locator()).toHaveClass(/\bdynamic\b/);
        await expect(aboutPanel.locator('#stats')).toHaveText('0 session rules, 1 dynamic rules.');

        // 3. Same-origin tabs (tab1 & tab3 on 127.0.0.1) share host rules, isolate per-tab document violations,
        //    and both receive tabless worker (SharedWorker) violations
        await tab1.bringToFront();
        await expect(report1.locator('#frames button.active')).toHaveAttribute('data-value', '127.0.0.1');

        // Allow worker-src 'self' on 127.0.0.1 in report1 -> report2 updates immediately
        await getSourceCheckbox(report1, "'self'", 'worker-src').check();
        await expect(await getSourceCheckbox(report2, "'self'", 'worker-src').locator()).toBeChecked();

        await tab1.reload();
        await tab3.reload();
        await tab1.bringToFront();

        // Trigger a document-scoped violation on tab1 only (#srcdoc-btn -> https://*.example.com in connect-src)
        await tab1.locator('#srcdoc-btn').click();
        await expect(tab1.locator('#badge-special')).toHaveText('Fetch Blocked (Check Report)');
        await expect(await getSourceCheckbox(report1, 'https://*.example.com', 'connect-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report2, 'https://*.example.com', 'connect-src').locator()).toHaveClass(/violation/);

        // Switch to tab3 (same origin 127.0.0.1): worker-src 'self' rule is shared, but tab1's srcdoc violation is NOT on tab3
        await tab3.bringToFront();
        await waitForPanelIdle(report1);
        await expect(await getSourceCheckbox(report1, "'self'", 'worker-src').locator()).toBeChecked();
        await expect(report1.locator('table#sources tbody tr th[title="https://*.example.com"]')).toHaveCount(0);

        // Trigger a tabless SharedWorker fetch violation on tab3 (tabId === -1 -> attributed to both tab1 and tab3!)
        await tab3.locator('#worker-shared-btn').click();
        await expect(tab3.locator('#badge-shared-worker')).toContainText('Conn #1');
        await tab3.locator('#worker-shared-fetch-btn').click();
        await expect(tab3.locator('#badge-worker')).toHaveText('Blocked');

        await expect(await getSourceCheckbox(report1, 'https://*.jsdelivr.net', 'connect-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report2, 'https://*.jsdelivr.net', 'connect-src').locator()).toHaveClass(/violation/);

        // Terminate the SharedWorker and switch back to tab1: tab1 also received the https://*.jsdelivr.net violation!
        await tab3.locator('#worker-shared-close-btn').click();
        await tab1.bringToFront();
        await expect(await getSourceCheckbox(report1, 'https://*.jsdelivr.net', 'connect-src').locator()).toHaveClass(/violation/);
        await expect(await getSourceCheckbox(report2, 'https://*.jsdelivr.net', 'connect-src').locator()).toHaveClass(/violation/);

        // 4. Adding https://*.jsdelivr.net to the Ignore group in groupsPanel immediately removes the violation
        //    highlight in BOTH open Report panels (and across both tab1 and tab3), and creating a new group updates #trustgroup
        const ignoreSection = groupsPanel.locator('section.group[data-name="Ignore"]');
        await ignoreSection.locator('input.neworigin').fill('https://*.jsdelivr.net');
        await ignoreSection.locator('button.addorigin').click({ force: true });
        await getSourceCheckbox(
            groupsPanel,
            'https://*.jsdelivr.net',
            'connect-src',
            'section.group[data-name="Ignore"] table.sources'
        ).check();

        await expect(report1.locator('table#sources tbody tr th[title="https://*.jsdelivr.net"]')).toHaveCount(0);
        await expect(report2.locator('table#sources tbody tr th[title="https://*.jsdelivr.net"]')).toHaveCount(0);

        await tab3.bringToFront();
        await expect(report1.locator('table#sources tbody tr th[title="https://*.jsdelivr.net"]')).toHaveCount(0);

        // Create a new trust group in groupsPanel and verify #trustgroup updates live in both Report panels
        await groupsPanel.locator('#newname').fill('SyncedGroup');
        await groupsPanel.locator('#addgroup').click({ force: true });
        await expect(report1.locator('#trustgroup option[value="SyncedGroup"]')).toHaveCount(1);
        await expect(report2.locator('#trustgroup option[value="SyncedGroup"]')).toHaveCount(1);
    });

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

    test('Architectural invariants: protected origins in Domain mode, server report-uri filtering, telemetry header stripping, 3-way cloud merge, schema migrations, and session persistence', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        // 1. Protected origin (chromewebstore.google.com) in Domain mode does NOT collapse to google.com and sets body.inert
        await setDefaultPolicy(serviceWorker, 1);
        await setOptions(serviceWorker, { defaultscope: 'domain' });
        await testbench.goto('http://chromewebstore.google.com:8123/');
        const report = await openPanel('report');
        await expect(report.locator('#frames button.active')).toHaveAttribute(
            'data-value',
            'chromewebstore.google.com'
        );
        await expect(report.locator('body')).toHaveClass(/\binert\b/);

        // 2. Server report-uri noise filtering (kReportUrls) & base.json rule 1 blocking csp_report:
        //    In Permissive mode (0), a violation of the server's own CSP (with its own report-uri)
        //    must be blocked on the wire by base.json and ignored by service-worker.js (no bogus violation in Report)
        await setDefaultPolicy(serviceWorker, 0);
        await testbench.goto(
            "http://127.0.0.1:8123/?csp=connect-src%20'none'%3B%20report-uri%20http%3A%2F%2F127.0.0.1%3A8123%2Fserver-report-sink"
        );
        await waitForPanelIdle(report);
        await expect(report.locator('body')).not.toHaveClass(/\binert\b/);
        expect((await getOnloadBadges(testbench))['fetch-self']).toBe('Blocked');
        const serverOnlyViolations = await getReportedViolations(report);
        expect(serverOnlyViolations).toEqual({});

        //    Conversely, when a host rule with workers disabled uses the csp-report WAR endpoint,
        //    report POSTs must complete cleanly (200 OK in onCompleted, zero onErrorOccurred).
        await setDefaultPolicy(serviceWorker, 1);
        await serviceWorker.evaluate(() => {
            const completed = [];
            const errors = [];
            const filter = { urls: [chrome.runtime.getURL('csp-report')], types: ['csp_report'] };
            const onCompleted = (d) => completed.push({ method: d.method, statusCode: d.statusCode });
            const onError = (d) => errors.push({ method: d.method, error: d.error });
            chrome.webRequest.onCompleted.addListener(onCompleted, filter);
            chrome.webRequest.onErrorOccurred.addListener(onError, filter);
            globalThis.__warReportStatus = () => ({ completed, errors });
            globalThis.__warReportCleanup = () => {
                chrome.webRequest.onCompleted.removeListener(onCompleted);
                chrome.webRequest.onErrorOccurred.removeListener(onError);
                delete globalThis.__warReportStatus;
                delete globalThis.__warReportCleanup;
            };
        });
        try {
            // The Report panel rebuilds its table (updateReport) after the options change from
            // setDefaultPolicy above; a click that lands just before that rebuild is discarded by
            // setCurrentRules, so retry until the session rule actually exists.
            await expect(async () => {
                await getSourceCheckbox(report, "'none'", 'connect-src').check();
                const rules = await serviceWorker.evaluate(() => chrome.declarativeNetRequest.getSessionRules());
                expect(rules.some((r) => r.condition.urlFilter === '||127.0.0.1^')).toBe(true);
            }).toPass();
            await testbench.goto('http://127.0.0.1:8123/');
            await getOnloadBadges(testbench);
            await expect
                .poll(() => serviceWorker.evaluate(() => globalThis.__warReportStatus()))
                .toEqual({
                    completed: expect.arrayContaining([{ method: 'POST', statusCode: 200 }]),
                    errors: [],
                });
        } finally {
            await serviceWorker.evaluate(() => globalThis.__warReportCleanup?.());
            await report.locator('#reset').click();
            await waitForPanelIdle(report);
        }

        // 3. Three-way Cloud Sync merge & deletion tracking via synced baseline (#mergeGroupOrigins, pushToCloud, pullFromCloud)
        const syncResult = await report.evaluate(async () => {
            const { RulesManager } = await import('/include/sidepanel.js');
            const { default: Options } = await import('/include/options.js');
            const { default: Policy } = await import('/include/policy.js');

            // Seed initial state: dynamic rule for a.example.com and group Team with origin1 + origin2, then pushToCloud()
            await RulesManager.addSessionRule('a.example.com', new Policy("script-src 'self'"));
            await RulesManager.commitSessionRulesForHost('a.example.com');
            await RulesManager.addSessionRule('b.example.com', new Policy("script-src 'self'"));
            await RulesManager.commitSessionRulesForHost('b.example.com');

            const groups = await Options.getGroups();
            groups.Team = {
                'https://origin1.example.com': ['script-src'],
                'https://origin2.example.com': ['connect-src'],
            };
            await Options.saveGroups();
            await RulesManager.pushToCloud();

            // Simulate remote device changes in chrome.storage.sync:
            // - Remote deletes rule:a.example.com
            // - Remote adds rule:c.example.com
            // - Remote edits group:Team (modifies origin2 to ['connect-src', 'img-src'] and adds origin3)
            await chrome.storage.sync.remove('rule:a.example.com');
            await chrome.storage.sync.set({
                'rule:c.example.com': { policy: "style-src 'self';" },
                'group:Team': {
                    'https://origin1.example.com': ['script-src'],
                    'https://origin2.example.com': ['connect-src', 'img-src'],
                    'https://origin3.example.com': ['font-src'],
                },
            });

            // Simulate concurrent local changes before pulling:
            // - Local deletes origin1 from Team and adds origin4
            // - Local adds unpushed dynamic rule d.example.com
            delete groups.Team['https://origin1.example.com'];
            groups.Team['https://origin4.example.com'] = ['media-src'];
            await Options.saveGroups();
            await RulesManager.addSessionRule('d.example.com', new Policy("img-src 'self'"));
            await RulesManager.commitSessionRulesForHost('d.example.com');

            await RulesManager.pullFromCloud();

            const finalRules = RulesManager.getRules()
                .filter((r) => !r.isSession)
                .map((r) => r.host)
                .sort();
            const finalTeam = structuredClone((await Options.getGroups()).Team);
            return { finalRules, finalTeam };
        });

        // a.example.com was in synced baseline and deleted remotely -> removed
        // b.example.com was kept, c.example.com was pulled from cloud, d.example.com was local-only (not in synced) -> preserved!
        expect(syncResult.finalRules).toEqual(['b.example.com', 'c.example.com', 'd.example.com']);
        // In group Team:
        // - origin1 deleted locally -> removed
        // - origin2 modified remotely while unchanged locally -> updated to ['connect-src', 'img-src']
        // - origin3 added remotely -> added
        // - origin4 added locally -> preserved
        expect(syncResult.finalTeam).toEqual({
            'https://origin2.example.com': ['connect-src', 'img-src'],
            'https://origin3.example.com': ['font-src'],
            'https://origin4.example.com': ['media-src'],
        });

        // 4. Options.migrate (v1 -> v2 -> v3) and forward-version write guard (version > kDefaultOptions.version)
        const migrationAndGuard = await report.evaluate(async () => {
            const { default: Options } = await import('/include/options.js');
            const v1Blob = {
                version: 1,
                defaultpolicy: 1,
                groups: {
                    LegacyGroup: ['https://*.legacy.example.com'],
                },
            };
            const groups = await Options.getGroups();
            Options.migrate(v1Blob, groups);

            // Test forward-version guard: set in-memory options.version = 99 and capture alert on Options.save()
            const opts = await Options.get();
            const origAlert = window.alert;
            let alertMsg = null;
            window.alert = (msg) => {
                alertMsg = msg;
            };
            try {
                opts.version = 99;
                const saveRet = await Options.save();
                opts.version = 3;
                return {
                    migratedVersion: v1Blob.version,
                    hasLegacyGroupsProp: 'groups' in v1Blob,
                    migratedGroupEntry: groups.LegacyGroup?.['https://*.legacy.example.com'],
                    saveRet,
                    alertMsg,
                };
            } finally {
                opts.version = 3;
                window.alert = origAlert;
            }
        });
        expect(migrationAndGuard.migratedVersion).toBe(3);
        expect(migrationAndGuard.hasLegacyGroupsProp).toBe(false);
        expect(migrationAndGuard.migratedGroupEntry).toEqual(['default-src', 'script-src', 'style-src', 'img-src']);
        expect(migrationAndGuard.saveRet).toBe(false);
        expect(migrationAndGuard.alertMsg).toContain('newer version');

        // 5. ViolationTracker session persistence round-trip (Tab.serialize / Tab.deserialize via chrome.storage.session)
        const trackerRoundTrip = await report.evaluate(async () => {
            const { default: ViolationTracker } = await import('/include/tracker.js');
            const { default: CspReport } = await import('/include/cspreport.js');

            const t1 = new ViolationTracker();
            await t1.addDocument(777, 'doc-main', 'http://127.0.0.1:8123/', undefined);
            await t1.addServerPolicy(777, 'http://127.0.0.1:8123/', "base-uri 'self'");
            await t1.addServiceWorker('http://127.0.0.1:8123/sw.js');
            const bodyBytes = new TextEncoder().encode(
                JSON.stringify({
                    'csp-report': {
                        'document-uri': 'http://127.0.0.1:8123/',
                        'blocked-uri': 'https://cdn.jsdelivr.net/npm/d3',
                        'effective-directive': 'script-src-elem',
                    },
                })
            ).buffer;
            const rep = new CspReport({
                initiator: 'http://127.0.0.1:8123',
                documentId: 'doc-main',
                requestBody: { raw: [{ bytes: bodyBytes }] },
            });
            await t1.addTabViolation(777, rep);

            // Flush to chrome.storage.session directly using Tab.serialize format and load into a fresh ViolationTracker
            const tabsState = {
                777: {
                    server: { '127.0.0.1': await t1.getServerPolicy(777, '127.0.0.1') },
                    policy: { '127.0.0.1': await t1.getDirectives(777, '127.0.0.1') },
                    documents: { 'doc-main': 'http://127.0.0.1:8123' },
                },
            };
            await chrome.storage.session.set({
                tabs: tabsState,
                workers: ['http://127.0.0.1:8123'],
            });

            const t2 = new ViolationTracker();
            return {
                hasDoc: await t2.hasDocument(777, 'doc-main'),
                tabsForOrigin: await t2.findTabsForOrigin('http://127.0.0.1:8123'),
                serverPolicy: await t2.getServerPolicy(777, '127.0.0.1'),
                directives: await t2.getDirectives(777, '127.0.0.1'),
                workers: await t2.getServiceWorkers(),
            };
        });
        expect(trackerRoundTrip).toEqual({
            hasDoc: true,
            tabsForOrigin: [777],
            serverPolicy: ["base-uri 'self'"],
            directives: { 'script-src-elem': ['https://*.jsdelivr.net'] },
            workers: ['127.0.0.1'],
        });
    });

    test('Legacy v1/v2 settings and v1.x passthru/set rules migrate cleanly without data loss and enforce properly', async ({
        testbench,
        openPanel,
    }) => {
        const report = await openPanel('report');

        // --- Part A: In-place extension update from v1 options & v1.x "set"/passthru dNR rules ---
        const testbenchTabId = await report.evaluate(async () => {
            const sidepanel = await import('/include/sidepanel.js');
            return (await sidepanel.getActiveTab()).id;
        });

        const partAResult = await report.evaluate(async (tabId) => {
            const sidepanel = await import('/include/sidepanel.js');
            const { default: Options } = await import('/include/options.js');
            await sidepanel.RulesManager.resetAllRules();

            // 1. Seed raw v1 options in chrome.storage.sync (no version field, array-based groups inside options,
            // plus obsolete v1 unregistersw key). Options.#onChanged automatically migrates v1 -> v2 -> v3.
            await chrome.storage.local.remove(['groups', 'synced']);
            await chrome.storage.sync.clear();
            await chrome.storage.sync.set({
                options: {
                    defaultpolicy: 1,
                    advanced: true,
                    badges: true,
                    confirmactions: false,
                    defaultscope: 'domain',
                    unregistersw: true,
                    groups: {
                        Ignore: ['https://www.google.com'],
                        LegacyCDN: ['https://*.jsdelivr.net'],
                    },
                },
            });

            // 2. Seed raw v1.x dNR rules directly via Chrome API:
            //    - operation: "set" (single rule per host, no override allow rule)
            //    - priority: 2 (dynamic) / 3 (session) / 4 (tab exemption)
            //    - condition.resourceTypes: ["main_frame", "sub_frame"] (instead of excludedResourceTypes)
            //    - legacy passthru directives (upgrade-insecure-requests, block-all-mixed-content,
            //      frame-ancestors, form-action, require-trusted-types-for, trusted-types, base-uri, report-to)
            //    - legacy 'nonce-...', 'strict-dynamic', and 'sha256-...' tokens
            //    - legacy https://_matrix3.internal/csp-report report-uri
            const legacyDynamicRule = {
                id: 1,
                priority: 2,
                action: {
                    type: 'modifyHeaders',
                    responseHeaders: [
                        {
                            header: 'Content-Security-Policy',
                            operation: 'set',
                            value:
                                "default-src 'self'; " +
                                "script-src 'nonce-rAnd0m123' 'strict-dynamic' https://www.google.com; " +
                                "style-src 'self' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='; " +
                                "img-src 'self' data:; " +
                                "font-src 'self'; " +
                                "connect-src 'self'; " +
                                "media-src 'self'; " +
                                "object-src 'none'; " +
                                "frame-src 'self'; " +
                                "worker-src 'none'; " +
                                "manifest-src 'self'; " +
                                'upgrade-insecure-requests ; ' +
                                'block-all-mixed-content ; ' +
                                "frame-ancestors 'self'; " +
                                "form-action 'self'; " +
                                "require-trusted-types-for 'script'; " +
                                'trusted-types default; ' +
                                "base-uri 'self'; " +
                                'report-to csp-endpoint; ' +
                                'report-uri https://_matrix3.internal/csp-report; ',
                        },
                    ],
                },
                condition: {
                    urlFilter: '||127.0.0.1^',
                    resourceTypes: ['main_frame', 'sub_frame'],
                },
            };

            const legacySessionRule = {
                id: 2,
                priority: 3,
                action: {
                    type: 'modifyHeaders',
                    responseHeaders: [
                        {
                            header: 'Content-Security-Policy',
                            operation: 'set',
                            value:
                                "default-src 'self'; " +
                                "script-src 'sha384-legacyhash==' https://ajax.googleapis.com; " +
                                "worker-src 'self'; " +
                                'upgrade-insecure-requests ; ' +
                                "frame-ancestors 'none'; " +
                                'report-uri https://_matrix3.internal/csp-report; ',
                        },
                    ],
                },
                condition: {
                    urlFilter: '||localhost^',
                    resourceTypes: ['main_frame', 'sub_frame'],
                },
            };

            const legacyExemptRule = {
                id: 3,
                priority: 4,
                action: { type: 'allow' },
                condition: {
                    resourceTypes: ['main_frame', 'sub_frame'],
                    tabIds: [tabId],
                },
            };

            await chrome.declarativeNetRequest.updateDynamicRules({
                removeRuleIds: [],
                addRules: [legacyDynamicRule],
            });
            await chrome.declarativeNetRequest.updateSessionRules({
                removeRuleIds: [],
                addRules: [legacySessionRule, legacyExemptRule],
            });

            // 3. Run the onInstalled("update") migration path: replaceAllRules(null, null)
            await sidepanel.RulesManager.replaceAllRules(null, null);
            await sidepanel.applyOptions();

            const rawSync = await chrome.storage.sync.get(null);
            const rawLocal = await chrome.storage.local.get(null);
            const liveDynamic = await chrome.declarativeNetRequest.getDynamicRules();
            const liveSession = await chrome.declarativeNetRequest.getSessionRules();
            const parsed127 = sidepanel.RulesManager.getHostRule('127.0.0.1');
            const parsedLocalhost = sidepanel.RulesManager.getHostRule('localhost');
            const isExempt = sidepanel.RulesManager.isTabExempt(tabId);

            // Remove the tab exemption after verifying it so we can test actual CSP enforcement on 127.0.0.1
            await sidepanel.RulesManager.delTabExemption(tabId);

            return {
                syncOptions: rawSync.options,
                syncGroupIgnore: rawSync['group:Ignore'],
                syncGroupLegacyCDN: rawSync['group:LegacyCDN'],
                localGroups: rawLocal.groups,
                localSynced: rawLocal.synced,
                liveDynamic,
                liveSession,
                parsed127Directives: parsed127.policy.directives,
                parsedLocalhostDirectives: parsedLocalhost.policy.directives,
                isExempt,
                warReportUrl: chrome.runtime.getURL('csp-report'),
            };
        }, testbenchTabId);

        // Verify v1 -> v3 options & groups storage migration
        expect(partAResult.syncOptions.version).toBe(3);
        expect(partAResult.syncOptions.defaultpolicy).toBe(1);
        expect(partAResult.syncOptions.advanced).toBe(true);
        expect(partAResult.syncOptions.groups).toBeUndefined();
        const expectedDirs = ['default-src', 'script-src', 'style-src', 'img-src'];
        expect(partAResult.localGroups).toEqual({
            Ignore: { 'https://www.google.com': expectedDirs },
            LegacyCDN: { 'https://*.jsdelivr.net': expectedDirs },
        });
        expect(partAResult.syncGroupIgnore).toEqual({ 'https://www.google.com': expectedDirs });
        expect(partAResult.syncGroupLegacyCDN).toEqual({ 'https://*.jsdelivr.net': expectedDirs });
        expect(partAResult.localSynced.groups).toEqual(partAResult.localGroups);

        // Verify legacy dynamic rule was expanded into an (allow, append) pair at 10*L + tier (127.0.0.1 has L=4 -> 41, 42)
        expect(partAResult.liveDynamic).toHaveLength(2);
        const dynAllow = partAResult.liveDynamic.find((r) => r.action.type === 'allow');
        const dynAppend = partAResult.liveDynamic.find((r) => r.action.type === 'modifyHeaders');
        expect(dynAllow.priority).toBe(41);
        expect(dynAllow.condition.excludedResourceTypes).toEqual(['csp_report', 'websocket']);
        expect(dynAllow.condition.resourceTypes).toBeUndefined();
        expect(dynAppend.priority).toBe(42);
        expect(dynAppend.action.responseHeaders[0].operation).toBe('append');
        expect(dynAppend.condition.excludedResourceTypes).toEqual(['csp_report', 'websocket']);
        expect(dynAppend.condition.resourceTypes).toBeUndefined();

        // Verify passthru directives were stripped and nonces/strict-dynamic/hashes migrated cleanly
        for (const passthru of [
            'upgrade-insecure-requests',
            'block-all-mixed-content',
            'frame-ancestors',
            'form-action',
            'require-trusted-types-for',
            'trusted-types',
            'base-uri',
            'report-to',
        ]) {
            expect(partAResult.parsed127Directives[passthru]).toBeUndefined();
            expect(partAResult.parsedLocalhostDirectives[passthru]).toBeUndefined();
        }
        // 'nonce-...' + 'strict-dynamic' -> 'unsafe-inline' + 'self' (plus preserved https://www.google.com)
        expect(partAResult.parsed127Directives['script-src']).toEqual([
            "'unsafe-inline'",
            'https://www.google.com',
            "'self'",
        ]);
        // 'sha256-...' -> 'unsafe-inline' (deduplicated alongside 'self')
        expect(partAResult.parsed127Directives['style-src']).toEqual(["'self'", "'unsafe-inline'"]);
        // Because worker-src is 'none' on 127.0.0.1, report-uri migrated from https://_matrix3.internal/csp-report to WAR URL
        expect(partAResult.parsed127Directives['report-uri']).toEqual([partAResult.warReportUrl]);
        // Because worker-src is 'self' on localhost, report-uri migrated from https:// to wss://_matrix3.internal/csp-report
        expect(partAResult.parsedLocalhostDirectives['report-uri']).toEqual(['wss://_matrix3.internal/csp-report']);
        // 'sha384-...' on localhost script-src migrated to 'unsafe-inline' (without adding 'self' since it was a hash, not a nonce)
        expect(partAResult.parsedLocalhostDirectives['script-src']).toEqual([
            "'unsafe-inline'",
            'https://ajax.googleapis.com',
        ]);

        // Verify legacy tab-exemption rule was upgraded to priority 1001 with excludedResourceTypes
        expect(partAResult.isExempt).toBe(true);
        const exemptRule = partAResult.liveSession.find((r) => r.condition?.tabIds);
        expect(exemptRule.priority).toBe(1001);
        expect(exemptRule.condition.excludedResourceTypes).toEqual(['csp_report', 'websocket']);
        expect(exemptRule.condition.resourceTypes).toBeUndefined();

        // 4. Verify the migrated rule on 127.0.0.1 actually works end-to-end on the testbench!
        // Navigate with a server-only directive (form-action 'none') to confirm our migrated append rule
        // neither clobbers server CSP nor injects stale passthru directives.
        await testbench.goto("http://127.0.0.1:8123/?csp=form-action%20'none'");
        const badgesA = await getOnloadBadges(testbench);
        // Allowed by migrated rule: ext-script (https://www.google.com), inline-auth & inline-plain ('unsafe-inline'),
        // inline-style ('unsafe-inline'), img-data (data:)
        expect(badgesA['ext-script']).toBe('Allowed');
        expect(badgesA['inline-auth']).toBe('Allowed');
        expect(badgesA['inline-plain']).toBe('Allowed');
        expect(badgesA['inline-style']).toBe('Allowed');
        expect(badgesA['img-data']).toBe('Allowed');
        // Blocked by migrated rule: eval & wasm (no 'unsafe-eval'), ext-style (jsdelivr not in style-src),
        // img-cross (https://www.google.com not in img-src, and in migrated Ignore group!), object-self (object-src 'none')
        expect(badgesA['eval']).toBe('Blocked');
        expect(badgesA['wasm']).toBe('Blocked');
        expect(badgesA['ext-style']).toBe('Blocked');
        expect(badgesA['img-cross']).toBe('Blocked');
        expect(badgesA['object-self']).toBe('Blocked');

        // Verify Report panel shows the server's form-action 'none' and suppresses https://www.google.com in img-src via migrated v1 Ignore group
        await expect(report.locator('#servercsp')).toContainText("form-action 'none'");
        await expect
            .poll(async () => {
                const v = await getReportedViolations(report);
                return v['https://*.googleapis.com'];
            })
            .toContain('style-src');
        const violationsA = await getReportedViolations(report);
        expect(violationsA['https://www.google.com'] ?? []).not.toContain('img-src');
        expect(violationsA['https://*.github.com']).toContain('connect-src');

        // --- Part B: Importing a v1.x JSON backup via the Export panel (saveExport) ---
        const exp = await openPanel('export');
        const v1Backup = {
            options: {
                version: 1,
                defaultpolicy: 1,
                advanced: true,
                badges: true,
                confirmactions: false,
                defaultscope: 'domain',
                unregistersw: false,
                groups: {
                    Ignore: ['https://*.FontAwesome.com'],
                    ImportedV1Group: ['https://cdn.jsdelivr.net', 'https://www.google.com'],
                },
            },
            dynamic: [
                {
                    id: 10,
                    priority: 2,
                    action: {
                        type: 'modifyHeaders',
                        responseHeaders: [
                            {
                                header: 'Content-Security-Policy',
                                operation: 'set',
                                value:
                                    "default-src 'self'; " +
                                    "script-src 'self' 'nonce-import456'; " +
                                    "style-src 'self' https://*.googleapis.com; " +
                                    "img-src 'self' https://www.google.com; " +
                                    "worker-src 'self'; " +
                                    'upgrade-insecure-requests ; ' +
                                    'block-all-mixed-content ; ' +
                                    "frame-ancestors 'self'; " +
                                    'report-uri https://_matrix3.internal/csp-report; ',
                            },
                        ],
                    },
                    condition: {
                        urlFilter: '||127.0.0.1^',
                        resourceTypes: ['main_frame', 'sub_frame'],
                    },
                },
            ],
            session: [],
            enabledRulesets: ['base', 'firstparty'],
        };

        await exp.locator('#export').fill(JSON.stringify(v1Backup));
        await exp.locator('#save').click();

        // Verify Export textarea refreshed with migrated v3 options, migrated groups, and sanitized append rule
        await expect
            .poll(async () => {
                const val = await exp.locator('#export').inputValue();
                try {
                    const parsed = JSON.parse(val);
                    return parsed.options?.version === 3 && Boolean(parsed.groups?.ImportedV1Group);
                } catch {
                    return false;
                }
            })
            .toBe(true);

        const exportedAfterV1Import = JSON.parse(await exp.locator('#export').inputValue());
        expect(exportedAfterV1Import.options.version).toBe(3);
        expect(exportedAfterV1Import.options.groups).toBeUndefined();
        // Previous LegacyCDN group was replaced by the imported v1 backup's groups
        expect(exportedAfterV1Import.groups).toEqual({
            Ignore: { 'https://*.FontAwesome.com': expectedDirs },
            ImportedV1Group: {
                'https://cdn.jsdelivr.net': expectedDirs,
                'https://www.google.com': expectedDirs,
            },
        });
        expect(exportedAfterV1Import.dynamic).toHaveLength(1);
        expect(exportedAfterV1Import.dynamic[0].action.responseHeaders[0].operation).toBe('append');
        expect(exportedAfterV1Import.dynamic[0].condition.excludedResourceTypes).toEqual([
            'csp_report',
            'websocket',
        ]);
        expect(exportedAfterV1Import.dynamic[0].action.responseHeaders[0].value).not.toContain(
            'upgrade-insecure-requests'
        );
        expect(exportedAfterV1Import.dynamic[0].action.responseHeaders[0].value).not.toContain('frame-ancestors');

        // Reload testbench and verify the imported v1 rule is enforced properly
        await testbench.goto('http://127.0.0.1:8123/');
        const badgesB = await getOnloadBadges(testbench);
        expect(badgesB['ext-style']).toBe('Allowed'); // https://*.jsdelivr.net allowed in style-src
        expect(badgesB['img-cross']).toBe('Allowed'); // https://www.google.com allowed in img-src
        expect(badgesB['inline-plain']).toBe('Allowed'); // 'nonce-import456' migrated to 'unsafe-inline'
        expect(badgesB['ext-script']).toBe('Blocked'); // https://www.google.com not in script-src

        // --- Part C: Pulling legacy v1.x rule strings from Cloud Sync (pullFromCloud) ---
        const partCResult = await exp.evaluate(async () => {
            const sidepanel = await import('/include/sidepanel.js');
            await chrome.storage.sync.set({
                'rule:sub.testbench.com': {
                    policy:
                        "default-src 'self'; " +
                        "script-src 'nonce-cloud789' 'strict-dynamic' https://*.jsdelivr.net; " +
                        'upgrade-insecure-requests ; ' +
                        "frame-ancestors 'none'; " +
                        "form-action 'none'; " +
                        'Block-All-Mixed-Content ;',
                },
            });
            await sidepanel.RulesManager.pullFromCloud();
            const rule = sidepanel.RulesManager.getHostRule('sub.testbench.com');
            return {
                directives: rule.policy.directives,
                dnrPair: rule.toRules(),
            };
        });

        expect(partCResult.directives['upgrade-insecure-requests']).toBeUndefined();
        expect(partCResult.directives['frame-ancestors']).toBeUndefined();
        expect(partCResult.directives['form-action']).toBeUndefined();
        expect(partCResult.directives['block-all-mixed-content']).toBeUndefined();
        expect(partCResult.directives['script-src']).toEqual([
            "'unsafe-inline'",
            'https://*.jsdelivr.net',
            "'self'",
        ]);
        expect(partCResult.dnrPair).toHaveLength(2);
        expect(partCResult.dnrPair[1].action.responseHeaders[0].operation).toBe('append');

        // Clean up back to defaults
        await exp.evaluate(async () => {
            const sidepanel = await import('/include/sidepanel.js');
            const { default: Options } = await import('/include/options.js');
            await sidepanel.RulesManager.resetAllRules();
            const opts = await Options.get();
            Object.assign(opts, {
                version: 3,
                defaultpolicy: 1,
                advanced: false,
                badges: true,
                confirmactions: false,
                defaultscope: 'domain',
                privatedomains: false,
            });
            delete opts.unregistersw;
            await Options.save();
            const groups = await Options.getGroups();
            for (const k of Object.keys(groups)) delete groups[k];
            groups.Ignore = {};
            await Options.saveGroups();
            await sidepanel.applyOptions();
        });
    });
});
