// WSHawk Companion - Popup Script
document.addEventListener('DOMContentLoaded', function () {
    const toggleBtn = document.getElementById('toggleBtn');
    const bridgeUrlInput = document.getElementById('bridgeUrl');
    const statusText = document.getElementById('statusText');

    chrome.storage.local.get(['bridgeUrl', 'capturingEnabled'], function (result) {
        if (result.bridgeUrl) bridgeUrlInput.value = result.bridgeUrl;

        let capturingEnabled = result.capturingEnabled !== undefined ? result.capturingEnabled : true;
        updateUI(capturingEnabled);
    });

    toggleBtn.addEventListener('click', function () {
        chrome.storage.local.get('capturingEnabled', function (result) {
            let newState = result.capturingEnabled !== undefined ? !result.capturingEnabled : false;
            chrome.storage.local.set({ capturingEnabled: newState }, function () {
                updateUI(newState);
            });
        });
    });

    bridgeUrlInput.addEventListener('change', function () {
        chrome.storage.local.set({ bridgeUrl: bridgeUrlInput.value });
    });

    function updateUI(enabled) {
        if (enabled) {
            toggleBtn.textContent = "STOP CAPTURING";
            toggleBtn.className = "toggle-btn btn-on";
            statusText.textContent = "Status: Capturing Handshakes";
            statusText.style.color = "#00ff00";
        } else {
            toggleBtn.textContent = "START CAPTURING";
            toggleBtn.className = "toggle-btn btn-off";
            statusText.textContent = "Status: Paused";
            statusText.style.color = "#ff3333";
        }
    }
});
