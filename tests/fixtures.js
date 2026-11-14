import fs from 'node:fs';
import path from 'node:path';
import { test as base, chromium, expect } from '@playwright/test';

const kExtensionPath = path.resolve(__dirname, '..');
const kToolsPath = path.join(kExtensionPath, 'tools');

const kDotPng = fs.readFileSync(path.join(kToolsPath, 'dot.png'));
const kFontWoff2 = fs.readFileSync(path.join(kToolsPath, 'font.woff2'));
const kBeepWav = fs.readFileSync(path.join(kToolsPath, 'beep.wav'));

export const test = base.extend({
    context: async ({}, use) => {
        const context = await chromium.launchPersistentContext('', {
            channel: 'chromium',
            args: [
                `--disable-extensions-except=${kExtensionPath}`,
                `--load-extension=${kExtensionPath}`,
            ],
        });

        // Stub external origins used by tools/index.html so "Allowed" probes
        // succeed deterministically offline without hitting real servers.
        await context.route(/^https:\/\//, async (route) => {
            const url = new URL(route.request().url());
            const cors = { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' };

            if (url.hostname === 'www.google.com' && url.pathname === '/favicon.ico') {
                return route.fulfill({ status: 200, contentType: 'image/png', body: kDotPng });
            }
            if (url.hostname === 'www.google.com' && url.pathname === '/jsapi') {
                return route.fulfill({ status: 200, contentType: 'application/javascript', body: '/* jsapi ok */' });
            }
            if (url.hostname === 'fonts.googleapis.com') {
                return route.fulfill({ status: 200, contentType: 'text/css', body: '/* css ok */' });
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
            if (url.hostname.endsWith('example.com')) {
                if (url.pathname.endsWith('.webmanifest')) {
                    return route.fulfill({ status: 200, headers: cors, contentType: 'application/manifest+json', body: '{"name":"test"}' });
                }
                return route.fulfill({ status: 200, headers: cors, contentType: 'text/html', body: '<!doctype html><title>Example</title>ok' });
            }
            return route.fulfill({ status: 200, headers: cors, contentType: 'text/plain', body: 'ok' });
        });

        await use(context);
        await context.close();
    },

    serviceWorker: async ({ context }, use) => {
        let [sw] = context.serviceWorkers();
        if (!sw) {
            sw = await context.waitForEvent('serviceworker');
        }
        await use(sw);
    },

    extensionId: async ({ serviceWorker }, use) => {
        const extensionId = new URL(serviceWorker.url()).host;
        await use(extensionId);
    },

    testbench: async ({ context }, use) => {
        const page = context.pages()[0] || await context.newPage();
        await page.goto('http://127.0.0.1:8123/reset');
        await use(page);
    },

    openPanel: async ({ context, extensionId, testbench }, use) => {
        const open = async (panelName = 'report') => {
            const panelPage = await context.newPage();
            await panelPage.goto(`chrome-extension://${extensionId}/panels/${panelName}.html`);
            // Keep the testbench tab as the active tab in the window so
            // sidepanel.getActiveTab() and chrome.tabs.reload() target it.
            await testbench.bringToFront();
            return panelPage;
        };
        await use(open);
    },
});

export { expect };
