// matrix³ dummy service worker for testing.
self.addEventListener('install', (event) => {
    console.log('SW: Install event');
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    console.log('SW: Activate event');
    event.waitUntil(clients.claim());
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Intercept the main HTML document request
    if (url.pathname === '/') {
        console.log('SW: Intercepting root navigation');
        event.respondWith(
            fetch(event.request).then(async (response) => {
                let text = await response.text();

                text = text.replace(
                    '<!-- SW_STATUS -->',
                    '<span class="badge allowed">Active (intercepting /)</span>'
                );

                let newHeaders = new Headers(response.headers);

                return new Response(text, {
                    status: response.status,
                    statusText: response.statusText,
                    headers: newHeaders
                });
            }).catch(err => {
                console.error("SW Fetch Error:", err);
                return new Response("SW Error: " + err);
            })
        );
        return;
    }

    event.respondWith(fetch(event.request));
});

self.addEventListener('message', (event) => {
    const { cmd, url } = event.data ?? {};
    if (cmd === 'websocket') {
        try {
            const ws = new WebSocket(url);
            ws.addEventListener('open', () => {
                event.source?.postMessage(`SW WebSocket opened: ${url}`);
                ws.close();
            });
            ws.addEventListener('error', () => {
                event.source?.postMessage(`SW WebSocket error / blocked: ${url}`);
            });
        } catch (err) {
            event.source?.postMessage(`SW WebSocket threw: ${err}`);
        }
    }
});
