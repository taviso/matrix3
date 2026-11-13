const startedAt = new Date().toLocaleTimeString();
let connections = 0;

async function handleMessage(target, e) {
    const { cmd, param } = e.data ?? {};

    try {
        switch (cmd) {
            case 'import':
                await import(param);
                target.postMessage(`${cmd} ok`);
                break;
            case 'fetch': {
                const res = await fetch(param);
                target.postMessage(`fetch(${param}) ok (HTTP ${res.status}, worker started at ${startedAt}, conn #${connections})`);
                break;
            }
            case 'close':
                target.postMessage(`closing SharedWorker (started at ${startedAt})`);
                self.close();
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
                    target.postMessage(`nested -> ${ev.data}`);
                    if (revoke) URL.revokeObjectURL(url);
                });
                child.addEventListener('error', (ev) => {
                    target.postMessage(`nested worker error: ${ev.message || 'blocked'}`);
                    if (revoke) URL.revokeObjectURL(url);
                });
                child.postMessage(param.message);
                break;
            }
            default:
                target.postMessage(`unknown cmd: ${cmd}`);
                break;
        }
    } catch (err) {
        target.postMessage(`${cmd} blocked (worker started at ${startedAt}, conn #${connections}): ${err}`);
    }
}

self.addEventListener('message', (e) => handleMessage(self, e));
self.addEventListener('connect', (e) => {
    connections++;
    const port = e.ports[0];
    port.addEventListener('message', (ev) => handleMessage(port, ev));
    port.start();
    port.postMessage({ type: 'status', startedAt, connections });
});
