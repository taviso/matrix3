self.addEventListener('message', async (e) => {
    const { cmd, param } = e.data ?? {};

    try {
        switch (cmd) {
            case 'import':
                await import(param);
                self.postMessage(`${cmd} ok`);
                break;
            case 'spawn': {
                let url = param.url;
                let revoke = false;
                if (param.blobCode) {
                    const blob = new Blob([param.blobCode], { type: 'text/javascript' });
                    url = URL.createObjectURL(blob);
                    revoke = true;
                }
                const child = new Worker(url);
                child.addEventListener('message', (ev) => {
                    self.postMessage(`nested -> ${ev.data}`);
                    if (revoke) URL.revokeObjectURL(url);
                });
                child.addEventListener('error', (ev) => {
                    self.postMessage(`nested worker error: ${ev.message || 'blocked'}`);
                    if (revoke) URL.revokeObjectURL(url);
                });
                child.postMessage(param.message);
                break;
            }
            default:
                self.postMessage(`unknown cmd: ${cmd}`);
                break;
        }
    } catch (err) {
        self.postMessage(`${cmd} blocked: ${err}`);
    }
});
