import fs from 'node:fs';
import path from 'node:path';
import { test as base, chromium, expect } from '@playwright/test';

const kExtensionPath = path.resolve(__dirname, '..');
const kToolsPath = path.join(kExtensionPath, 'tools');

const kDotPng = fs.readFileSync(path.join(kToolsPath, 'dot.png'));
const kFontWoff2 = fs.readFileSync(path.join(kToolsPath, 'font.woff2'));
const kBeepWav = fs.readFileSync(path.join(kToolsPath, 'beep.wav'));

export const kPolicyRulesets = ['permissive', 'firstparty', 'sandbox-lite', 'sandbox', 'strict'];

export async function setDefaultPolicy(serviceWorker, level) {
    const enable = kPolicyRulesets[level];
    const disable = kPolicyRulesets.filter((r) => r !== enable);
    await serviceWorker.evaluate(async ({ level, enable, disable }) => {
        const { options = {} } = await chrome.storage.sync.get('options');
        options.version ??= 3;
        options.defaultpolicy = level;
        await chrome.storage.sync.set({ options });
        await chrome.declarativeNetRequest.updateEnabledRulesets({
            enableRulesetIds: [enable],
            disableRulesetIds: disable,
        });
    }, { level, enable, disable });
}

export async function setOptions(serviceWorker, partial) {
    await serviceWorker.evaluate(async (updates) => {
        const { options = {} } = await chrome.storage.sync.get('options');
        Object.assign(options, { version: 3 }, updates);
        await chrome.storage.sync.set({ options });
    }, partial);
}

export async function waitForPanelIdle(panelPage) {
    await panelPage.evaluate(async () => {
        const script = document.querySelector('script[type="module"][src]');
        if (script) {
            await import(script.src);
        }
        await Promise.resolve();
        if (navigator.locks) {
            await navigator.locks.request('matrix3:report', () => {});
            await navigator.locks.request('matrix3:rules', () => {});
        }
    });
}

// Read all settled page-load probe badges from #onload-grid (excluding
// SecureContext-dependent manifest-* probes unless requested).
export async function getOnloadBadges(testbench, includeManifest = false) {
    await expect
        .poll(
            async () =>
                testbench.evaluate((incManifest) => {
                    const els = document.querySelectorAll('#onload-grid .badge[id^="badge-"]');
                    if (els.length === 0) return false;
                    for (const el of els) {
                        const key = el.id.slice('badge-'.length);
                        if (!incManifest && key.startsWith('manifest-')) continue;
                        if (el.textContent.trim() === 'Pending') return false;
                    }
                    return true;
                }, includeManifest),
            { timeout: 5000 }
        )
        .toBe(true);
    return testbench.evaluate((incManifest) => {
        const result = {};
        for (const el of document.querySelectorAll('#onload-grid .badge[id^="badge-"]')) {
            const key = el.id.slice('badge-'.length);
            if (!incManifest && key.startsWith('manifest-')) continue;
            result[key] = el.textContent.trim();
        }
        return result;
    }, includeManifest);
}

// Read all (source, directive) pairs currently marked with .violation in #sources.
export async function getReportedViolations(reportPage) {
    await waitForPanelIdle(reportPage);
    return reportPage.locator('table#sources').evaluate((table) => {
        const cols = Array.from(table.querySelectorAll('thead th'), (th) => th.id);
        const out = {};
        for (const row of table.querySelectorAll('tbody tr')) {
            const src = row.querySelector('th')?.title;
            const dirs = [];
            row.querySelectorAll('td').forEach((td, i) => {
                const input = td.querySelector('input.violation');
                if (input) dirs.push(cols[i + 1]);
            });
            if (src && dirs.length) out[src] = dirs;
        }
        return out;
    });
}

// Locate the checkbox for a specific (source, directive) cell inside a .sources table.
export function getSourceCheckbox(panelPage, source, directive, tableSelector = 'table#sources') {
    const table = panelPage.locator(tableSelector);
    return {
        async locator() {
            await table.locator('thead th').first().waitFor({ state: 'attached' });
            const colIdx = await table.locator('thead th').evaluateAll(
                (ths, dir) => ths.findIndex((th) => th.id === dir),
                directive
            );
            if (colIdx < 1) {
                throw new Error(`Directive column "${directive}" not found in ${tableSelector}`);
            }
            const row = table.locator('tbody tr').filter({
                has: panelPage.locator(`th[title="${source}"]`),
            });
            return row.locator('td').nth(colIdx - 1).locator('input[type="checkbox"]');
        },
        async check() {
            const loc = await this.locator();
            await loc.check({ force: true });
            await waitForPanelIdle(panelPage);
        },
        async uncheck() {
            const loc = await this.locator();
            await loc.uncheck({ force: true });
            await waitForPanelIdle(panelPage);
        },
    };
}

export const test = base.extend({
    browserContext: [async ({}, use) => {
        const context = await chromium.launchPersistentContext('', {
            channel: 'chromium',
            args: [
                `--disable-extensions-except=${kExtensionPath}`,
                `--load-extension=${kExtensionPath}`,
                '--disable-background-timer-throttling',
                '--disable-backgrounding-occluded-windows',
                '--disable-renderer-backgrounding',
                '--host-resolver-rules=MAP *.testbench.com 127.0.0.1, MAP testbench.com 127.0.0.1, MAP *.github.io 127.0.0.1, MAP github.io 127.0.0.1, MAP chromewebstore.google.com 127.0.0.1, MAP ::1 127.0.0.1, MAP 2001:db8::* 127.0.0.1',
            ],
        });

        // Stub external origins used by tools/index.html so "Allowed" probes
        // succeed deterministically offline without hitting real servers.
        const kLocalHosts = new Set(['127.0.0.1', '[::1]', 'localhost']);
        await context.route(/^https?:\/\//, async (route) => {
            const url = new URL(route.request().url());
            if (url.port === '8123') {
                return route.continue();
            }
            if (kLocalHosts.has(url.hostname) || url.hostname.endsWith('.localhost')) {
                return route.continue();
            }
            const cors = { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' };

            if (url.hostname === 'www.google.com' && url.pathname === '/favicon.ico') {
                return route.fulfill({ status: 200, headers: cors, contentType: 'image/png', body: kDotPng });
            }
            if (url.hostname === 'www.google.com' && url.pathname === '/jsapi') {
                return route.fulfill({ status: 200, headers: cors, contentType: 'application/javascript', body: '/* jsapi ok */' });
            }
            if (url.hostname === 'fonts.googleapis.com') {
                return route.fulfill({ status: 200, headers: cors, contentType: 'text/css', body: '/* css ok */' });
            }
            if (url.hostname === 'fonts.gstatic.com') {
                return route.fulfill({ status: 200, headers: cors, contentType: 'font/woff2', body: kFontWoff2 });
            }
            if (url.hostname === 'actions.google.com') {
                return route.fulfill({ status: 200, headers: cors, contentType: 'audio/wav', body: kBeepWav });
            }
            if (url.hostname === 'api.github.com') {
                return route.fulfill({ status: 200, headers: cors, contentType: 'application/json', body: '{"ok":true}' });
            }
            if (url.hostname === 'cdn.jsdelivr.net') {
                return route.fulfill({ status: 200, headers: cors, contentType: 'application/javascript', body: 'export default "ok";' });
            }
            if (url.hostname.endsWith('example.com') || url.hostname.endsWith('github.io') || url.hostname.endsWith('cloudfront.net')) {
                if (url.pathname.endsWith('.webmanifest')) {
                    return route.fulfill({ status: 200, headers: cors, contentType: 'application/manifest+json', body: '{"name":"test"}' });
                }
                return route.fulfill({ status: 200, headers: cors, contentType: 'text/html', body: '<!doctype html><title>Example</title>ok' });
            }
            return route.fulfill({ status: 200, headers: cors, contentType: 'text/plain', body: 'ok' });
        });

        await use(context);
        await context.close();
    }, { scope: 'worker' }],

    context: async ({ browserContext }, use) => {
        await use(browserContext);
    },

    serviceWorker: async ({ browserContext }, use) => {
        let [sw] = browserContext.serviceWorkers();
        if (!sw) {
            sw = await browserContext.waitForEvent('serviceworker');
        }

        // Reset extension state cleanly before each test
        await sw.evaluate(async () => {
            const [session, dynamic] = await Promise.all([
                chrome.declarativeNetRequest.getSessionRules(),
                chrome.declarativeNetRequest.getDynamicRules(),
            ]);
            await chrome.declarativeNetRequest.updateSessionRules({
                removeRuleIds: session.map((r) => r.id),
            });
            await chrome.declarativeNetRequest.updateDynamicRules({
                removeRuleIds: dynamic.map((r) => r.id),
            });
            await chrome.declarativeNetRequest.updateEnabledRulesets({
                enableRulesetIds: ['permissive'],
                disableRulesetIds: ['firstparty', 'sandbox-lite', 'sandbox', 'strict'],
            });
            await chrome.storage.sync.clear();
            await chrome.storage.local.clear();
            await chrome.storage.session.clear();
            await chrome.storage.sync.set({
                options: {
                    version: 3,
                    defaultpolicy: 0,
                    advanced: false,
                    badges: true,
                    confirmactions: false,
                    defaultscope: 'domain',
                    privatedomains: false,
                },
            });
            await chrome.storage.local.set({
                groups: { Ignore: {} },
                synced: { rules: [], groups: {} },
            });
        });

        await use(sw);
    },

    extensionId: async ({ serviceWorker }, use) => {
        const extensionId = new URL(serviceWorker.url()).host;
        await use(extensionId);
    },

    testbench: async ({ browserContext, serviceWorker }, use) => {
        const pages = browserContext.pages();
        const page = pages[0] || await browserContext.newPage();
        for (const p of pages.slice(1)) {
            await p.close();
        }
        await page.bringToFront();
        await page.goto('http://127.0.0.1:8123/reset');
        await use(page);
    },

    openPanel: async ({ browserContext, extensionId, testbench }, use) => {
        const open = async (panelName = 'report') => {
            const panelPage = await browserContext.newPage();
            // Restore testbench as the active tab BEFORE navigating the panel page
            // so sidepanel.getActiveTab() sees testbench during initial load and
            // no spurious chrome.tabs.onActivated fires afterwards.
            await testbench.bringToFront();
            await panelPage.goto(`chrome-extension://${extensionId}/panels/${panelName}.html`);
            await panelPage.locator('#panel option').first().waitFor({ state: 'attached' });
            await waitForPanelIdle(panelPage);
            return panelPage;
        };
        await use(open);
    },
});

export { expect };
