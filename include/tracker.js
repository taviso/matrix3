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
}

export default class ViolationTracker {
    #tabs;

    constructor () {
        this.#tabs = new Map();
    }

    #getOrCreateTab(tabId) {
        if (this.#tabs.has(tabId) == false) {
            this.#tabs.set(tabId, new Tab());
        }
        return this.#tabs.get(tabId);
    }

    async addTabViolation(tabId, report) {
        let tab = this.#getOrCreateTab(tabId);
        let blocked = report.blocked?.origin;
        let docUrl;

        if (!report.blocked)
            return false;

        try {
            docUrl = new URL(report.report["document-uri"]);
        } catch (e) {
            return false;
        }

        let origin = docUrl.origin;

        // Normalize some sources
        if (blocked == origin) {
            blocked = "'self'";
        } else if (blocked == "null") {
            // Opaque origins (inline, eval, data, blob, etc) have origin "null".
            // Map them back to their CSP source keywords using the protocol.
            blocked = CspReport.protocolSource(report.blocked.protocol);
            if (blocked === undefined) {
                console.warn("tracker", "unknown blocked pseudo-scheme", report.blocked);
                return false;
            }
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

        tab.policy[domain] ??= {};
        tab.policy[domain][report.directive] ??= new Set();
        tab.policy[domain][report.directive].add(blocked);

        // Caller uses our return value to decide whether to badge and notify;
        // ignored origins are recorded silently.
        let options = await Options.get();
        let ignored = options?.groups?.Ignore?.[blocked];
        let dir = Policy.collapseDirective(report.directive);
        if (ignored?.includes(`!${dir}`))
            return true;
        if (ignored?.includes("default-src") || ignored?.includes(dir))
            return false;

        return true;
    }

    // Called from webNavigation.onBeforeNavigate; drop everything we know about the tab.
    resetTab(tabId) {
        this.#tabs.delete(tabId);
    }

    resetViolations(tabId) {
        let tab = this.#tabs.get(tabId);
        if (tab) {
            tab.policy = {};
            tab.documents.clear();
        }
    }

    resetServerPolicy(tabId) {
        let tab = this.#tabs.get(tabId);
        if (tab) tab.server = {};
    }

    // Track which documentIds are currently live for the tab so we can drop
    // csp_reports from documents that no longer exist (e.g. POSTs in flight
    // from the previous page that arrive after a reload).
    addDocument(tabId, documentId) {
        this.#getOrCreateTab(tabId).documents.add(documentId);
    }

    hasDocument(tabId, documentId) {
        return this.#tabs.get(tabId)?.documents.has(documentId) ?? false;
    }

    async addServerPolicy(tabId, url, header) {
        let tab = this.#getOrCreateTab(tabId);
        let domain = await psl.getScopedDomain(new URL(url).hostname);
        tab.server[domain] ??= new Set();
        tab.server[domain].add(header);
    }

    getServerPolicy(tabId, domain) {
        let tab = this.#tabs.get(tabId);
        return Array.from(tab?.server[domain] ?? []);
    }

    getDirectives(tabId, domain) {
        let tab = this.#tabs.get(tabId);
        let bucket = tab?.policy[domain] ?? {};

        return Object.fromEntries(
            Object.entries(bucket).map(([key, value]) => [key, Array.from(value)])
        );
    }

}

