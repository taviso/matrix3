import { defineConfig } from '@playwright/test';

export default defineConfig({
    testDir: './tests',
    timeout: 30000,
    fullyParallel: false,
    workers: 1,
    reporter: 'list',
    webServer: {
        command: 'python3 tools/csptest.py 8123',
        url: 'http://127.0.0.1:8123/',
        reuseExistingServer: !process.env.CI,
    },
});
