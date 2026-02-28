// WSHawk Browser Companion - Background Script
// Captures WebSocket handshakes and forwards them to the Python bridge

let bridgeUrl = "http://127.0.0.1:5000/api/interceptor/handshake";
let capturingEnabled = true;

// Load config from storage
chrome.storage.local.get(['bridgeUrl', 'capturingEnabled'], function (result) {
    if (result.bridgeUrl) bridgeUrl = result.bridgeUrl;
    if (result.capturingEnabled !== undefined) capturingEnabled = result.capturingEnabled;
});

// Watch for storage changes
chrome.storage.onChanged.addListener(function (changes, namespace) {
    if (changes.bridgeUrl) bridgeUrl = changes.bridgeUrl.newValue;
    if (changes.capturingEnabled) capturingEnabled = changes.capturingEnabled.newValue;
});

chrome.webRequest.onBeforeSendHeaders.addListener(
    function (details) {
        if (!capturingEnabled) return { requestHeaders: details.requestHeaders };

        // Detect WebSocket Upgrade request
        const isUpgrade = details.requestHeaders.some(h =>
            h.name.toLowerCase() === 'upgrade' && h.value.toLowerCase() === 'websocket'
        );

        if (isUpgrade) {
            console.log("[WSHawk] WebSocket Handshake Detected:", details.url);

            const handshake = {
                url: details.url,
                method: details.method,
                headers: {},
                timestamp: new Date().toISOString()
            };

            details.requestHeaders.forEach(h => {
                handshake.headers[h.name] = h.value;
            });

            // Send to WSHawk
            fetch(bridgeUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(handshake)
            }).then(r => r.json())
                .then(data => console.log("[WSHawk] Handshake synced:", data))
                .catch(err => console.error("[WSHawk] Sync failed (is WSHawk running?):", err));
        }
        return { requestHeaders: details.requestHeaders };
    },
    { urls: ["<all_urls>"] },
    ["blocking", "requestHeaders"]
);
