import CspReport from '/include/cspreport.js'
import Options from '/include/options.js'
import Policy from '/include/policy.js'
import * as psl from '/include/psl.js'

// Track sub-resource violations and surface them in the report panel, so
// the user can grant per-host permissions without navigating to each blocked
// origin and editing them one at a time.

// Tab violation and policy tracking.
class Tab {
    server = {};
    policy = {};
    documents = new Set();

    // Chrome will suspend our service worker when idle, and we'll lose any
    // data we're tracking in memory. That's not a big problem, just a minor
    // UX issue - if a user refreshes the sidepanel after a suspend we will
    // have forgotten about older violations.
    // To avoid that, we can save the data to session storage when idle, then
    // restore it when we wake up. The problem is session storage is JSON based,
    // so we can't just store a Set object directly. These routines
    // serialize/unserialize our data to something that works.
    deserialize(data) {
        for (let [k, v] of Object.entries(data.server ?? {}))
            this.server[k] = new Set(v);
        for (let [domain, dirs] of Object.entries(data.policy ?? {})) {
            this.policy[domain] = {};
            for (let [dir, srcs] of Object.entries(dirs))
                this.policy[domain][dir] = new Set(srcs);
        }
        this.documents.clear();
        data.documents?.forEach(d => this.documents.add(d));
        return this;
    }

    serialize() {
        return {
            server: Object.fromEntries(
                Object.entries(this.server).map(([k, v]) => [k, Array.from(v)])
            ),
            policy: Object.fromEntries(
                Object.entries(this.policy).map(([domain, dirs]) => [
                    domain,
                    Object.fromEntries(
                        Object.entries(dirs).map(([dir, srcs]) => [dir, Array.from(srcs)])
                    ),
                ])
            ),
            documents: Array.from(this.documents),
        };
    }
}

export default class ViolationTracker {
    #tabs;
    #state;
    #timer;

    constructor () {
        this.#tabs = new Map();
        this.#state = this.#loadState();
    }

    async #loadState() {
        let { tabs = {} } = await chrome.storage.session.get("tabs")
            .catch(e => (console.warn("tracker", "failed to load session state", e), {}));
        console.debug("tracker", `restoring ${Object.keys(tabs).length} tabs from session storage`, tabs);
        for (let [id, val] of Object.entries(tabs))
            this.#tabs.set(Number(id), new Tab().deserialize(val));
    }

    // MV3 service workers terminate after ~30s idle, so we backup our working
    // data to chrome.storage.session when we're idle. This data isn't critical
    // if something fails, it just means we might forget about an old violation.
    #syncSession = () => {
        let tabs = Object.fromEntries(
            Array.from(this.#tabs, ([id, tab]) => [id, tab.serialize()])
        );
        console.debug("tracker", `saving ${Object.keys(tabs).length} tabs to session storage`, tabs);
        chrome.storage.session.set({ tabs })
            .catch(e => console.warn("tracker", "failed to save session state", e));
    };

    // This clearTimeout/setTimeout is intended to wait until we're idle for 10s, then
    // save our state to session storage.
    #saveState() {
        clearTimeout(this.#timer);
        this.#timer = setTimeout(this.#syncSession, 10000);
    }

    #getOrCreateTab(tabId) {
        if (this.#tabs.has(tabId) == false) {
            this.#tabs.set(tabId, new Tab());
        }
        return this.#tabs.get(tabId);
    }

    async addTabViolation(tabId, report) {
        await this.#state;
        let tab = this.#getOrCreateTab(tabId);
        let policy = tab.policy;
        let blocked = report.blocked?.origin;
        let docUrl;

        if (!report.blocked)
            return false;

        try {
            docUrl = new URL(report.report["document-uri"]);
        } catch (e) {
            return false;
        }

        if (!docUrl.hostname)
            return false;

        let origin = docUrl.origin;

        // Normalize some sources
        if (blocked == "null") {
            // Opaque origins (inline, eval, data, blob, etc) have origin "null".
            // Map them back to their CSP source keywords using the protocol.
            blocked = CspReport.protocolSource(report.blocked.protocol);
            if (blocked === undefined) {
                console.warn("tracker", "unknown blocked pseudo-scheme", report.blocked);
                return false;
            }
        } else if (blocked == origin) {
            blocked = "'self'";
        } else {
            // Collapse subdomains to a wildcard at the user's chosen scope. In
            // "host" scope getScopedDomain is a passthrough and the wildcard
            // branch below is a no-op.
            const u = new URL(blocked);
            const scoped = await psl.getScopedDomain(u.hostname);
            let hostpart = scoped;
            if (u.hostname != scoped)
                hostpart = `*.${scoped}`;
            blocked = `${u.protocol}//${hostpart}`;
        }

        // Bucket by the document's scope so the panel can find it with the
        // same key it puts in the dropdown.
        let domain = await psl.getScopedDomain(docUrl.hostname);
        let options = await Options.get();

        // Drop if the tab or its violations were reset while we were awaiting.
        if (this.#tabs.get(tabId) !== tab || tab.policy !== policy)
            return false;

        policy[domain] ??= {};
        policy[domain][report.directive] ??= new Set();
        policy[domain][report.directive].add(blocked);
        this.#saveState();

        // Caller uses our return value to decide whether to badge and notify;
        // ignored origins are recorded silently.
        let ignored = options?.groups?.Ignore?.[blocked];
        let dir = Policy.collapseDirective(report.directive);
        if (ignored?.includes(`!${dir}`))
            return true;
        if (ignored?.includes("default-src") || ignored?.includes(dir))
            return false;

        return true;
    }

    // Called from tabs.onRemoved / tabs.onReplaced; drop everything we know about the tab.
    async resetTab(tabId) {
        await this.#state;
        this.#tabs.delete(tabId);
        this.#saveState();
    }

    async resetViolations(tabId) {
        await this.#state;
        let tab = this.#getOrCreateTab(tabId);
        tab.policy = {};
        tab.documents.clear();
        this.#saveState();
    }

    async resetServerPolicy(tabId) {
        await this.#state;
        let tab = this.#getOrCreateTab(tabId);
        tab.server = {};
        this.#saveState();
    }

    // Track which documentIds are currently live for the tab so we can drop
    // csp_reports from documents that no longer exist (e.g. POSTs in flight
    // from the previous page that arrive after a reload).
    async addDocument(tabId, documentId) {
        await this.#state;
        this.#getOrCreateTab(tabId).documents.add(documentId);
        this.#saveState();
    }

    async hasDocument(tabId, documentId) {
        await this.#state;
        return this.#tabs.get(tabId)?.documents.has(documentId) ?? false;
    }

    async addServerPolicy(tabId, url, header) {
        await this.#state;
        let tab = this.#getOrCreateTab(tabId);
        let server = tab.server;
        let domain = await psl.getScopedDomain(new URL(url).hostname);
        if (this.#tabs.get(tabId) !== tab || tab.server !== server)
            return;
        server[domain] ??= new Set();
        server[domain].add(header);
        this.#saveState();
    }

    async getServerPolicy(tabId, domain) {
        await this.#state;
        let tab = this.#tabs.get(tabId);
        return Array.from(tab?.server[domain] ?? []);
    }

    async getDirectives(tabId, domain) {
        await this.#state;
        let tab = this.#tabs.get(tabId);
        let bucket = tab?.policy[domain] ?? {};

        return Object.fromEntries(
            Object.entries(bucket).map(([key, value]) => [key, Array.from(value)])
        );
    }

}

