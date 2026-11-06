import CspReport from '/include/cspreport.js'
import ViolationTracker from '/include/tracker.js'
import RequestServer from '/server.js'
import Rules from '/include/rules.js'
import { MessageTypes } from '/include/commands.js'
import Options from '/include/options.js'

// Tracker state is backed by chrome.storage.session so it survives MV3
// service worker idle unloads.
let tracker = new ViolationTracker();
let server = new RequestServer(tracker);

// Apply stored options on browser-start / install -- otherwise the saved
// defaultpolicy slider doesn't take effect until the sidepanel opens.
async function applyStoredOptions() {
    let options = await Options.get();
    let rules;
    if (options?.defaultpolicy === undefined)
        return;
    rules = new Rules();
    await rules.init();
    await rules.applyDefaultPolicy(options.defaultpolicy);
}

chrome.runtime.onStartup.addListener(applyStoredOptions);
chrome.runtime.onInstalled.addListener(applyStoredOptions);
chrome.storage.onChanged.addListener(applyStoredOptions);

// Set a badge on the toolbar icon for the given tab. Skipped when the
// `badges` option is off so users can opt out of the visual clutter or
// if the sidepanel is already open.
async function setBadge(tabId, text, color) {
    let options = await Options.get();
    let contexts;
    if (!options?.badges)
        return;
    contexts = await chrome.runtime.getContexts({
        contextTypes: ["SIDE_PANEL"],
        tabIds: [tabId]
    }).catch(() => []);
    if (contexts?.length)
        return;
    chrome.action.setBadgeText({ text, tabId }).catch(() => {});
    chrome.action.setBadgeBackgroundColor({ color, tabId }).catch(() => {});
}

function clearBadge(tabId) {
    chrome.action.setBadgeText({ text: '', tabId }).catch(() => {});
}

// Track what security policy hosts request, and make it available to users.
chrome.webRequest.onHeadersReceived.addListener(async (details) => {
        let csp = details.responseHeaders.filter(hdr => hdr.name.toLowerCase() == "content-security-policy");

        console.debug("service", "onheadersreceived", details.tabId, details.url, details);

        // Ignore requests not associated with a tab, or not part of the active lifecycle (e.g. prerendering).
        if (details.tabId === -1 || details.documentLifecycle !== 'active')
            return;

        // handle mainframe navigations.
        if (details.frameId === 0)
            await tracker.resetServerPolicy(details.tabId);

        // Track each policy header the server sends; the tracker collects them
        // in a Set so the UI can display and analyze all of them.
        for (let hdr of csp)
            await tracker.addServerPolicy(details.tabId, details.url, hdr.value);

        // Update the UI if the main frame state reset or new policies were discovered.
        if (details.frameId === 0 || csp.length)
            chrome.runtime.sendMessage({
                command: MessageTypes.NOTIFY_UPDATE,
                   data: { id: details.tabId }
            }).catch(() => {});
    }, {
        types: [ "main_frame", "sub_frame" ],
        urls: [ "<all_urls>" ]
    }, [ "responseHeaders" ]
);

// Monitor for CSP violation reports.
chrome.webRequest.onBeforeRequest.addListener(async (details) => {
        console.debug("service", "onbeforerequest", details.tabId, details);

        // Drop reports from documents that no longer exist -- POSTs from the
        // previous page can still be in flight when the user reloads.
        if (!await tracker.hasDocument(details.tabId, details.documentId))
            return;

        // Check if we're learning about a new violation.
        if (!await tracker.addTabViolation(details.tabId, new CspReport(details)))
            return;

        // Report new violations known by marking the icon.
        setBadge(details.tabId, "!", "#dc2626");

        // Update any listening sidepanel.
        chrome.runtime.sendMessage({
            command: MessageTypes.NOTIFY_UPDATE,
               data: { id: details.tabId }
        }).catch(() => {});

    }, {
        types: [ "csp_report" ],
         urls: [ "<all_urls>" ]
    }, [ "requestBody" ]
);

// Record each frame's documentId at commit time. resetTab clears them
// alongside everything else, so a top-frame navigation wipes the whole tree.
chrome.webNavigation.onCommitted.addListener((details) => {
    console.debug("service", "oncommitted", details.tabId, details);
    tracker.addDocument(details.tabId, details.documentId);
});

// Make the matrix button open the sidepanel.
chrome.sidePanel.setPanelBehavior({openPanelOnActionClick: true }).catch(console.error);

// Reset before the request so the CSP captured by onHeadersReceived survives.
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    console.debug("service", "onbeforenavigate", details.tabId, details);
    if (details.frameId !== 0)
        return;

    tracker.resetViolations(details.tabId);
    clearBadge(details.tabId);
});
chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
    console.debug("service", "onremoved", tabId, removeInfo);
    tracker.resetTab(tabId);
});
chrome.tabs.onReplaced.addListener((addedTabId, removedTabId) => {
    console.debug("service", "onreplaced", addedTabId, removedTabId);
    tracker.resetTab(removedTabId);
});
