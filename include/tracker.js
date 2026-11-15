import CspReport from '/include/cspreport.js'
import Options from '/include/options.js'
import Policy from '/include/policy.js'
import * as psl from '/include/psl.js'

// Track sub-resource violations and surface them in the report panel, so
// the user can grant per-host permissions without navigating to each blocked
// origin and editing them one at a time.
const kMaxDomains = 128;
const kMaxSources = 1024;

// Tab violation and policy tracking.
class Tab {
    server = Object.create(null);
    policy = Object.create(null);
    documents = new Map();
    redirects = new Map();

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
            this.policy[domain] = Object.create(null);
            for (let [dir, srcs] of Object.entries(dirs))
                this.policy[domain][dir] = new Set(srcs);
        }
        this.documents.clear();
        if (Array.isArray(data.documents)) {
            data.documents.forEach(d => this.documents.set(d, ""));
        } else {
            for (let [id, url] of Object.entries(data.documents ?? {}))
                this.documents.set(id, url);
        }
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
            documents: Object.fromEntries(this.documents),
        };
    }
}

export default class ViolationTracker {
    #tabs;
    #workers;
    #state;
    #timer;

    constructor () {
        this.#tabs = new Map();
        this.#workers = new Set();
        this.#state = this.#loadState();
    }

    async #loadState() {
        let { tabs = {}, workers = [] } = await chrome.storage.session.get(["tabs", "workers"])
            .catch(e => (console.warn("tracker", "failed to load session state", e), {}));
        console.debug("tracker", `restoring ${Object.keys(tabs).length} tabs from session storage`, tabs);
        for (let [id, val] of Object.entries(tabs))
            this.#tabs.set(Number(id), new Tab().deserialize(val));
        for (let domain of workers)
            this.#workers.add(domain);
    }

    // MV3 service workers terminate after ~30s idle, so we backup our working
    // data to chrome.storage.session when we're idle. This data isn't critical
    // if something fails, it just means we might forget about an old violation.
    #syncSession = () => {
        let tabs = Object.fromEntries(
            Array.from(this.#tabs, ([id, tab]) => [id, tab.serialize()])
        );
        let workers = Array.from(this.#workers);
        console.debug("tracker", `saving ${Object.keys(tabs).length} tabs to session storage`, tabs);
        chrome.storage.session.set({ tabs, workers })
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
        let blockedUrl = report.blocked;
        let docUrl = URL.parse(report.report["document-uri"]);

        // Per W3C CSP3 §5.3, when a request is blocked after a redirect,
        // blocked-uri in the report is the pre-redirect URL; follow any
        // redirects recorded by onBeforeRedirect (up to Fetch's 20-redirect
        // limit, net::URLRequest::kMaxRedirects) to find the blocked target.
        for (let i = 0; i < 20 && tab.redirects.has(blockedUrl?.href); i++)
            blockedUrl = URL.parse(tab.redirects.get(blockedUrl.href));

        let blocked = blockedUrl?.origin;

        // Local-scheme contexts (blob: workers, about:srcdoc frames, etc.)
        // report a bare scheme like "blob" or "about" as document-uri, so
        // fall back to the request initiator's origin or the owning document's
        // committed URL (for opaque origins like data: workers or sandboxed frames).
        if (!docUrl?.hostname)
            docUrl = report.initiator;
        if (!docUrl?.hostname)
            docUrl = URL.parse(tab.documents.get(report.documentId));

        if (!blockedUrl || !docUrl?.hostname)
            return false;

        let origin = docUrl.origin;

        // Normalize some sources
        if (blocked == "null") {
            // Opaque origins (inline, eval, data, blob, etc) have origin "null".
            // Map them back to their CSP source keywords using the protocol.
            blocked = CspReport.protocolSource(blockedUrl.protocol);
            if (blocked === undefined) {
                console.warn("tracker", "unknown blocked pseudo-scheme", blockedUrl);
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
            if (u.port)
                hostpart += `:${u.port}`;
            blocked = `${u.protocol}//${hostpart}`;
        }

        // Bucket by the document's scope so the panel can find it with the
        // same key it puts in the dropdown.
        let domain = await psl.getScopedDomain(docUrl.hostname);
        let groups = await Options.getGroups();

        // Drop if the tab or its violations were reset while we were awaiting.
        if (this.#tabs.get(tabId) !== tab || tab.policy !== policy)
            return false;

        // Cap tracked frame domains per tab so iframe spam cannot grow unbounded.
        if (!policy[domain] && Object.keys(policy).length >= kMaxDomains) {
            console.debug("tracker", "domain cap reached, dropping violation", tabId, domain);
            return false;
        }
        policy[domain] ??= Object.create(null);
        let sources = policy[domain][report.directive] ??= new Set();
        // Cap unique origins per directive and fold any overflow into the scheme.
        if (sources.size >= kMaxSources && blocked.includes("://")) {
            console.debug("tracker", "source cap reached", tabId, domain, report.directive, blocked);
            blocked = blockedUrl.protocol;
        }
        if (sources.has(blocked))
            return false;
        sources.add(blocked);
        this.#saveState();

        // Caller uses our return value to decide whether to badge and notify;
        // ignored origins are recorded silently.
        let ignored = groups?.Ignore?.[blocked];
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
        for (let url of tab.documents.values()) {
            let origin = URL.parse(url)?.origin;
            if (origin)
                this.#workers.delete(origin);
        }
        tab.policy = Object.create(null);
        tab.documents.clear();
        tab.redirects.clear();
        this.#saveState();
    }

    async addRedirect(tabId, fromUrl, toUrl) {
        await this.#state;
        if (tabId === -1 || !fromUrl || !toUrl)
            return;
        let redirects = this.#getOrCreateTab(tabId).redirects;
        if (redirects.size >= 128)
            redirects.delete(redirects.keys().next().value);
        redirects.set(fromUrl, toUrl);
    }

    async resetServerPolicy(tabId) {
        await this.#state;
        let tab = this.#getOrCreateTab(tabId);
        tab.server = Object.create(null);
        this.#saveState();
    }

    // Track which documentIds are currently live for the tab (along with their
    // effective origin URL) so we can drop csp_reports from documents that no
    // longer exist and attribute opaque-origin reports back to their owner.
    async addDocument(tabId, documentId, url, parentDocumentId) {
        await this.#state;
        let docs = this.#getOrCreateTab(tabId).documents;

        if (docs.size >= kMaxSources) {
            console.debug("tracker", "document cap reached, dropping document", tabId, documentId, url);
            return;
        }

        // Local-scheme subframes (about:srcdoc, about:blank, data:) have no
        // hostname of their own, so inherit the parent document's URL.
        if (!URL.parse(url)?.hostname && docs.has(parentDocumentId))
            url = docs.get(parentDocumentId);

        docs.set(documentId, url);
        this.#saveState();
    }

    async hasDocument(tabId, documentId) {
        await this.#state;
        return this.#tabs.get(tabId)?.documents.has(documentId) ?? false;
    }

    // Resolve tabless reports (ServiceWorker / SharedWorker, where tabId is -1)
    // to any open tabs that currently have a committed document on that origin.
    async findTabsForOrigin(origin) {
        await this.#state;
        if (!origin || origin === "null")
            return [];
        let matching = [];
        for (let [tabId, tab] of this.#tabs) {
            for (let url of tab.documents.values()) {
                if (URL.parse(url)?.origin === origin) {
                    matching.push(tabId);
                    break;
                }
            }
        }
        return matching;
    }

    async addServerPolicy(tabId, url, header) {
        await this.#state;
        let tab = this.#getOrCreateTab(tabId);
        let server = tab.server;
        let domain = await psl.getScopedDomain(new URL(url).hostname);
        if (this.#tabs.get(tabId) !== tab || tab.server !== server)
            return;

        // Cap tracked frame domains per tab so iframe spam cannot grow unbounded.
        if (!server[domain] && Object.keys(server).length >= kMaxDomains) {
            console.debug("tracker", "domain cap reached, dropping server policy", tabId, domain);
            return;
        }

        server[domain] ??= new Set();

        // Cap recorded server headers per domain in case subframes reload with unique nonces.
        if (server[domain].size >= kMaxDomains) {
            console.debug("tracker", "header cap reached, dropping server policy", tabId, domain);
            return;
        }

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

    async addServiceWorker(url) {
        await this.#state;
        let u = URL.parse(url);
        if (u?.protocol !== "http:" && u?.protocol !== "https:")
            return false;
        if (this.#workers.has(u.origin))
            return false;
        if (this.#workers.size >= kMaxSources) {
            console.debug("tracker", "worker cap reached, dropping worker", u.origin);
            return false;
        }
        this.#workers.add(u.origin);
        this.#saveState();
        return true;
    }

    async delServiceWorker(domain) {
        await this.#state;
        let removed = [];
        for (let origin of this.#workers) {
            let u = URL.parse(origin);
            if (u?.hostname && await psl.getScopedDomain(u.hostname) === domain) {
                this.#workers.delete(origin);
                removed.push(origin);
            }
        }
        if (removed.length)
            this.#saveState();
        return removed;
    }

    async getServiceWorkers() {
        await this.#state;
        let domains = new Set();
        for (let origin of this.#workers) {
            let u = URL.parse(origin);
            if (u?.hostname)
                domains.add(await psl.getScopedDomain(u.hostname));
        }
        return Array.from(domains);
    }

}

