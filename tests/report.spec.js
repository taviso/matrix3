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

test.describe('Report Panel: Frame Tabs, Top-Bar Actions, Exemptions, & Multi-Tab Sync', () => {
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

        // Exemption must be scoped to the disabled tab (tabIds): a second tab on the
        // same origin must still enforce Strict mode and show #disable (not #resume).
        const secondTab = await testbench.context().newPage();
        try {
            await secondTab.goto(testbench.url());
            await expect(secondTab.locator('#onload-summary')).toHaveText('23 Probes');
            await expect(secondTab.locator('#badge-inline-plain')).toHaveText('Blocked');
            expect(await secondTab.evaluate(() => document.querySelector('img[data-probe="img-cross"]')?.naturalWidth)).toBe(0);
            await expect(report.locator('#resume')).toBeDisabled();
            await expect(report.locator('#disable')).toBeVisible();
        } finally {
            await secondTab.close();
        }

        // Switching back to the disabled tab restores its exempt UI state.
        await testbench.bringToFront();
        await expect(report.locator('#resume')).toBeEnabled();
        await expect(report.locator('#disable')).toBeHidden();

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

    test('Keyboard input cannot edit rules on a Disabled tab or a protected origin (interactivity: inert)', async ({
        serviceWorker,
        testbench,
        openPanel,
    }) => {
        await setDefaultPolicy(serviceWorker, 1);
        await testbench.reload();
        const report = await openPanel('report');

        const hostRules = () => serviceWorker.evaluate(async () =>
            (await chrome.declarativeNetRequest.getSessionRules()).filter((r) => r.condition.urlFilter)
        );
        // Focus a control the way a keyboard user would, then press a key on it.
        const focusAndPress = async (locator, key) => {
            await locator.focus();
            await report.keyboard.press(key);
            await waitForPanelIdle(report);
        };
        const selfScript = getSourceCheckbox(report, "'self'", 'script-src');

        // 1. Disabled tab: everything except Resume and Reload is inert.
        await report.locator('#disable').click();
        await expect(report.locator('#resume')).toBeEnabled();

        await focusAndPress(await selfScript.locator(), 'Space');
        await focusAndPress(report.locator('input#sandbox-enabled'), 'Space');
        expect(await hostRules()).toEqual([]);
        expect(await report.evaluate(() => document.activeElement?.tagName)).not.toBe('INPUT');

        // Resume itself must still work from the keyboard.
        await focusAndPress(report.locator('#resume'), 'Enter');
        await expect(report.locator('#resume')).toBeDisabled();

        // 2. Protected origin: the whole editing UI is inert.
        await testbench.goto('http://chromewebstore.google.com:8123/');
        await expect(report.locator('body')).toHaveClass(/\binert\b/);

        await focusAndPress(await selfScript.locator(), 'Space');
        expect(await hostRules()).toEqual([]);
        expect(await report.evaluate(() => document.activeElement?.tagName)).not.toBe('INPUT');
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
});
