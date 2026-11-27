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

test.describe('Export, 3-Way Cloud Sync, Schema Migrations, & Architectural Invariants', () => {
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
                .map((r) => [r.host, r.action.responseHeaders[0].value])
                .sort(([a], [b]) => a.localeCompare(b));
            const finalTeam = structuredClone((await Options.getGroups()).Team);
            return { finalRules, finalTeam };
        });

        // a.example.com was in synced baseline and deleted remotely -> removed
        // b.example.com was kept, c.example.com was pulled from cloud, d.example.com was local-only (not in synced) -> preserved!
        expect(syncResult.finalRules).toEqual([
            ['b.example.com', expect.stringContaining("script-src 'self'")],
            ['c.example.com', expect.stringContaining("style-src 'self'")],
            ['d.example.com', expect.stringContaining("img-src 'self'")],
        ]);
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

    test('Cloud Sync: pull, manually delete rule/group/origin in UI, then push removes them from cloud', async ({
        serviceWorker,
        openPanel,
    }) => {
        // Seed remote cloud state as if pushed from another device
        await serviceWorker.evaluate(async () => {
            await chrome.storage.sync.set({
                'rule:keep.example.com': { policy: "script-src 'self';" },
                'rule:remove.example.com': { policy: "img-src 'self';" },
                'group:KeepGroup': {
                    'https://keep.test': ['img-src'],
                    'https://drop-origin.test': ['font-src'],
                },
                'group:DeleteGroup': {
                    'https://gone.test': ['connect-src'],
                },
                'group:Ignore': {
                    'https://noisy.test': ['media-src'],
                },
            });
        });

        // 1. Pull from cloud via the Export panel UI
        const exp = await openPanel('export');
        await exp.locator('#pull').click();
        await expect
            .poll(() =>
                serviceWorker.evaluate(async () => {
                    const rules = await chrome.declarativeNetRequest.getDynamicRules();
                    return rules
                        .filter((r) => r.action.type === 'modifyHeaders')
                        .map((r) => r.condition.urlFilter.slice(2, -1))
                        .sort();
                })
            )
            .toEqual(['keep.example.com', 'remove.example.com']);

        // 2. Manually delete remove.example.com in the Manage Rules panel
        const manage = await openPanel('manage');
        const removeRow = manage.locator('#dynamic tbody tr').filter({ hasText: 'remove.example.com' });
        await expect(removeRow).toHaveCount(1);
        await removeRow.locator('input[type="checkbox"]').check();
        await manage.locator('#removedynamic').click();
        await expect(removeRow).toHaveCount(0);

        // 3. Manually delete DeleteGroup, drop-origin.test from KeepGroup, and noisy.test from Ignore in Groups panel
        const groupsPanel = await openPanel('groups');
        await groupsPanel.locator('.group[data-name="DeleteGroup"] .delgroup').click();
        await expect(groupsPanel.locator('.group[data-name="DeleteGroup"]')).toHaveCount(0);

        const keepGroupEl = groupsPanel.locator('.group[data-name="KeepGroup"]');
        const dropOriginRow = keepGroupEl.locator('tr').filter({ hasText: 'drop-origin.test' });
        await dropOriginRow.hover();
        await dropOriginRow.locator('.delorigin').click();
        await expect(dropOriginRow).toHaveCount(0);

        const ignoreGroupEl = groupsPanel.locator('.group[data-name="Ignore"]');
        const noisyRow = ignoreGroupEl.locator('tr').filter({ hasText: 'noisy.test' });
        await noisyRow.hover();
        await noisyRow.locator('.delorigin').click();
        await expect(noisyRow).toHaveCount(0);

        // Wait for Export panel's mirror to process NOTIFY_RULES / storage changes, then Push
        await expect
            .poll(() => exp.locator('#export').inputValue())
            .not.toContain('remove.example.com');
        await exp.locator('#push').click();
        await expect(exp.locator('#lastpush')).toContainText('1 rules, 2 groups');

        // 4. Verify deletions propagated to chrome.storage.sync and report-uri was stripped
        const cloudState = await serviceWorker.evaluate(() => chrome.storage.sync.get(null));
        expect(cloudState['rule:remove.example.com']).toBeUndefined();
        expect(cloudState['rule:keep.example.com']?.policy).toContain("script-src 'self'");
        expect(cloudState['rule:keep.example.com']?.policy).not.toContain('report-uri');
        expect(cloudState['rule:keep.example.com']?.policy).not.toContain('report-to');
        expect(cloudState['group:DeleteGroup']).toBeUndefined();
        expect(cloudState['group:KeepGroup']).toEqual({ 'https://keep.test': ['img-src'] });
        expect(cloudState['group:Ignore']).toEqual({});
    });

    test('Cloud Sync: symmetric 3-way pushToCloud merge, remote preservation, and conflict resolution', async ({
        serviceWorker,
        openPanel,
    }) => {
        const exp = await openPanel('export');

        const result = await exp.evaluate(async () => {
            const { RulesManager } = await import('/include/sidepanel.js');
            const { default: Options } = await import('/include/options.js');
            const { default: Policy } = await import('/include/policy.js');

            // Initial state on Device A: 2 dynamic rules, 1 session draft, and 2 groups
            await RulesManager.addSessionRule('shared.test', new Policy("script-src 'self'"));
            await RulesManager.commitSessionRulesForHost('shared.test');
            await RulesManager.addSessionRule('local-del.test', new Policy("img-src 'self'"));
            await RulesManager.commitSessionRulesForHost('local-del.test');
            await RulesManager.addSessionRule('draft.test', new Policy("font-src 'self'"));

            const groups = await Options.getGroups();
            groups.Shared = {
                'https://keep.test': ['img-src', 'script-src'],
                'https://local-edit.test': ['img-src'],
                'https://remote-edit.test': ['font-src'],
                'https://conflict.test': ['connect-src'],
                'https://local-del.test': ['media-src'],
            };
            groups.LocalDelGroup = {
                'https://old.test': ['img-src'],
            };
            await Options.saveGroups();
            await RulesManager.pushToCloud();

            const afterFirstPush = await chrome.storage.sync.get(null);

            // Simulate Device B editing cloud directly while Device A is offline:
            // - Adds unpulled rule:remote-only.test and group:RemoteOnlyGroup
            // - Reorders keep.test dirs (must count as unchanged), edits remote-edit.test & conflict.test, adds remote-add.test
            await chrome.storage.sync.set({
                'rule:remote-only.test': { policy: "style-src 'self';" },
                'group:RemoteOnlyGroup': { 'https://r.test': ['img-src'] },
                'group:Shared': {
                    'https://keep.test': ['script-src', 'img-src'],
                    'https://local-edit.test': ['img-src'],
                    'https://remote-edit.test': ['font-src', 'style-src'],
                    'https://conflict.test': ['connect-src', 'frame-src'],
                    'https://local-del.test': ['media-src'],
                    'https://remote-add.test': ['object-src'],
                },
            });

            // Concurrent local edits on Device A before pushing:
            await RulesManager.resetHostRules('local-del.test');
            delete groups.LocalDelGroup;
            groups.Shared['https://local-edit.test'] = ['img-src', 'media-src'];
            groups.Shared['https://conflict.test'] = ['connect-src', 'worker-src'];
            delete groups.Shared['https://local-del.test'];
            groups.Shared['https://local-add.test'] = ['script-src'];
            await Options.saveGroups();

            // Push TWICE before pulling: unpulled remote-only items and remote edits must survive both pushes
            await RulesManager.pushToCloud();
            const afterSecondPush = await chrome.storage.sync.get(null);
            await RulesManager.pushToCloud();
            const afterThirdPush = await chrome.storage.sync.get(null);
            const { synced: baselineBeforePull } = await chrome.storage.local.get('synced');

            // Finally pull: Device A should now receive remote-only items and remote group edits, keeping session draft
            await RulesManager.pullFromCloud();
            const finalDynamic = RulesManager.getRules()
                .filter((r) => !r.isSession)
                .map((r) => r.host)
                .sort();
            const finalSession = RulesManager.getRules()
                .filter((r) => r.isSession)
                .map((r) => r.host)
                .sort();
            const finalGroups = structuredClone(await Options.getGroups());

            return {
                afterFirstPush,
                afterSecondPush,
                afterThirdPush,
                baselineBeforePull,
                finalDynamic,
                finalSession,
                finalGroups,
            };
        });

        // Session draft must never be pushed; report-uri must be stripped
        expect(result.afterFirstPush['rule:draft.test']).toBeUndefined();
        expect(result.afterFirstPush['rule:shared.test']?.policy).not.toContain('report-uri');

        // Both pushes after concurrent edits must delete local-del items while preserving all unpulled remote state
        for (const snap of [result.afterSecondPush, result.afterThirdPush]) {
            expect(snap['rule:local-del.test']).toBeUndefined();
            expect(snap['group:LocalDelGroup']).toBeUndefined();
            expect(snap['rule:draft.test']).toBeUndefined();
            expect(snap['rule:remote-only.test']).toEqual({ policy: "style-src 'self';" });
            expect(snap['group:RemoteOnlyGroup']).toEqual({ 'https://r.test': ['img-src'] });
            expect(snap['group:Shared']).toEqual({
                'https://keep.test': ['script-src', 'img-src'],
                'https://local-edit.test': ['img-src', 'media-src'],
                'https://remote-edit.test': ['font-src', 'style-src'],
                'https://conflict.test': ['connect-src', 'worker-src'], // local wins conflict on Push
                'https://remote-add.test': ['object-src'],
                'https://local-add.test': ['script-src'],
            });
        }

        // Unpulled remote items must remain outside synced baseline until Pull
        expect(result.baselineBeforePull.rules).not.toContain('remote-only.test');
        expect(result.baselineBeforePull.groups.RemoteOnlyGroup).toBeUndefined();

        // After Pull, Device A merges remote items while keeping its session draft
        expect(result.finalDynamic).toEqual(['remote-only.test', 'shared.test']);
        expect(result.finalSession).toEqual(['draft.test']);
        expect(result.finalGroups.RemoteOnlyGroup).toEqual({ 'https://r.test': ['img-src'] });
        expect(result.finalGroups.Shared['https://remote-edit.test']).toEqual(['font-src', 'style-src']);
        expect(result.finalGroups.Shared['https://remote-add.test']).toEqual(['object-src']);
    });

    test('Cloud Sync: pullFromCloud edge cases (Ignore immunity, group deletion/resurrection, local-only & tab-exemption survival)', async ({
        testbench,
        openPanel,
    }) => {
        const exp = await openPanel('export');

        const result = await exp.evaluate(async () => {
            const sidepanel = await import('/include/sidepanel.js');
            const { RulesManager } = sidepanel;
            const { default: Options } = await import('/include/options.js');
            const { default: Policy } = await import('/include/policy.js');

            const tab = await sidepanel.getActiveTab();

            // 1. Seed initial synced baseline and push
            await RulesManager.addSessionRule('synced-keep.test', new Policy("script-src 'self'"));
            await RulesManager.commitSessionRulesForHost('synced-keep.test');
            await RulesManager.addSessionRule('synced-drop.test', new Policy("img-src 'self'"));
            await RulesManager.commitSessionRulesForHost('synced-drop.test');

            const groups = await Options.getGroups();
            groups.Ignore = { 'https://ign.test': ['img-src'] };
            groups.DropRemote = { 'https://a.test': ['img-src'] };
            groups.DelLocalUnchanged = { 'https://b.test': ['img-src'] };
            groups.DelLocalEditedRemotely = { 'https://c.test': ['img-src'] };
            groups.ConflictGroup = { 'https://both.test': ['connect-src'] };
            await Options.saveGroups();
            await RulesManager.pushToCloud();

            // 2. Add unpushed local-only items + session draft + active tab exemption
            await RulesManager.addSessionRule('local-only.test', new Policy("font-src 'self'"));
            await RulesManager.commitSessionRulesForHost('local-only.test');
            await RulesManager.addSessionRule('session-draft.test', new Policy("media-src 'self'"));
            await RulesManager.addTabExemption(tab.id);
            groups.LocalOnlyGroup = { 'https://loc.test': ['style-src'] };

            // Local deletions & conflicting edit
            delete groups.DelLocalUnchanged;
            delete groups.DelLocalEditedRemotely;
            groups.ConflictGroup['https://both.test'] = ['connect-src', 'worker-src'];
            await Options.saveGroups();

            // 3. Remote changes in chrome.storage.sync:
            // - Delete synced-drop.test, DropRemote, and Ignore (Ignore must survive locally!)
            // - Leave DelLocalUnchanged untouched (must NOT resurrect as {})
            // - Add a new origin to DelLocalEditedRemotely (must resurrect with ONLY the new origin)
            // - Modify ConflictGroup differently (cloud wins on Pull)
            await chrome.storage.sync.remove(['rule:synced-drop.test', 'group:DropRemote', 'group:Ignore']);
            await chrome.storage.sync.set({
                'group:DelLocalEditedRemotely': {
                    'https://c.test': ['img-src'],
                    'https://c-new.test': ['script-src'],
                },
                'group:ConflictGroup': {
                    'https://both.test': ['connect-src', 'frame-src'],
                },
            });

            // 4. Pull TWICE in a row to verify local-only items and deletions remain stable
            await RulesManager.pullFromCloud();
            await RulesManager.pullFromCloud();

            const afterPullDynamic = RulesManager.getRules()
                .filter((r) => !r.isSession)
                .map((r) => r.host)
                .sort();
            const afterPullSession = RulesManager.getRules()
                .filter((r) => r.isSession)
                .map((r) => r.host)
                .sort();
            const tabStillExempt = RulesManager.isTabExempt(tab.id);
            const afterPullGroups = structuredClone(await Options.getGroups());

            // 5. Verify tab exemption can still be removed cleanly after pullFromCloud() renumbered IDs
            await RulesManager.delTabExemption(tab.id);
            const tabExemptAfterResume = RulesManager.isTabExempt(tab.id);

            // 6. Push after pull: DelLocalUnchanged stayed deleted locally and in synced baseline,
            //    so pushing now must remove group:DelLocalUnchanged from cloud.
            await RulesManager.pushToCloud();
            const cloudAfterFinalPush = await chrome.storage.sync.get(null);

            return {
                afterPullDynamic,
                afterPullSession,
                tabStillExempt,
                tabExemptAfterResume,
                afterPullGroups,
                cloudAfterFinalPush,
            };
        });

        expect(result.afterPullDynamic).toEqual(['local-only.test', 'synced-keep.test']);
        expect(result.afterPullSession).toEqual(['session-draft.test']);
        expect(result.tabStillExempt).toBe(true);
        expect(result.tabExemptAfterResume).toBe(false);

        expect(result.afterPullGroups.Ignore).toEqual({ 'https://ign.test': ['img-src'] });
        expect(result.afterPullGroups.DropRemote).toBeUndefined();
        expect(result.afterPullGroups.LocalOnlyGroup).toEqual({ 'https://loc.test': ['style-src'] });
        expect(result.afterPullGroups.DelLocalUnchanged).toBeUndefined();
        expect(result.afterPullGroups.DelLocalEditedRemotely).toEqual({ 'https://c-new.test': ['script-src'] });
        expect(result.afterPullGroups.ConflictGroup).toEqual({ 'https://both.test': ['connect-src', 'frame-src'] });

        expect(result.cloudAfterFinalPush['group:DelLocalUnchanged']).toBeUndefined();
        expect(result.cloudAfterFinalPush['rule:local-only.test']?.policy).toContain("font-src 'self'");
        expect(result.cloudAfterFinalPush['group:LocalOnlyGroup']).toEqual({ 'https://loc.test': ['style-src'] });
    });
});
