import Policy from '/include/policy.js'
import Options from '/include/options.js'
import { MessageTypes } from '/include/commands.js'
import { callWithLock } from '/include/utils.js'

// dNR priorities are ordinal. Host rules scale by hostname label count L
// (e.g. "foo.com" => L=2, "sub.foo.com" => L=3) so a more-specific subdomain's
// (allow, append) pair always overrides a parent domain's rule across both
// tiers, while a session rule overrides a dynamic rule for the same host:
//   1001: tab bypass allow
//   1000: reporting header removal (base.json)
//   10*L + 4: session host CSP append
//   10*L + 3: session host allow override
//   10*L + 2: dynamic host CSP append
//   10*L + 1: dynamic host allow override
//   1: static default CSP append
const kDynamicPriority        = 2;
const kSessionPriority        = 4;
const kOverridePriorityOffset = 1;
const kLabelPriorityScale     = 10;
const kMaxPriorityLabels      = 90;
const kBypassPriority         = 1001;

// Resource types excluded from matrix³ CSP and allow rules (so report
// blocking rules in base.json are never overridden).
const kExcludedResourceTypes = [
    "csp_report", "websocket"
];

// Sync key recording when we last pushed rules.
const kLastPushKey = "meta:lastpush";

// A declarativeNetRequest rule (session or dynamic).
class Rule {
    id;
    overrideId;
    isSession;
    action = {};
    condition = {};

    // rule is a raw JSON DNR rule object from chrome.storage or dNR APIs.
    constructor(rule, session = false, overrideId = undefined)
    {
        this.id = rule?.id;
        this.overrideId = overrideId;
        this.action.type = "modifyHeaders";
        this.action.responseHeaders = [{
            header: "Content-Security-Policy",
            operation: "append",
        }];
        this.condition.excludedResourceTypes = [...kExcludedResourceTypes];
        this.condition.urlFilter = rule?.condition?.urlFilter;
        this.isSession = session;

        // Normalize the raw CSP value through Policy abstractions.
        this.fromPolicyString(rule?.action?.responseHeaders?.[0]?.value);
    };

    get ids() {
        return [this.id, this.overrideId].filter(Boolean);
    }

    // Cap label count at 90 (max priority 904) so host rules can never reach
    // base.json's reporting header removal (1000) or tab bypass (1001).
    get priority() {
        let labels = 1;
        let tier = kDynamicPriority;

        if (this.host) {
            labels = Math.min(this.host.split(".").length, kMaxPriorityLabels);
        }
        if (this.isSession) {
            tier = kSessionPriority;
        }

        return labels * kLabelPriorityScale + tier;
    }

    set host(host) {
        this.condition.urlFilter = "||" + host + "^";
    }

    get host() {
        return this.condition.urlFilter?.slice(2, -1);
    }

    get policy() {
        return this.toPolicy();
    }

    toPolicy() {
        return new Policy(this.action.responseHeaders[0].value);
    }

    fromPolicy(policy) {
        this.action.responseHeaders[0].value = policy.toHeader();
    }

    fromPolicyString(headerString) {
        this.fromPolicy(new Policy(headerString).sanitizeForAppend());
    }

    toRule() {
        return {
            id: this.id,
            action: this.action,
            condition: this.condition,
            priority: this.priority,
        };
    }

    // In Chrome dNR, "set" only runs the highest-priority matching rule,
    // whereas "append" runs *every* matching rule across all priorities.
    // Without an override, a host rule would append its CSP alongside the
    // static default (e.g. firstparty.json), and the browser would enforce the
    // intersection of both -- making it impossible to loosen the default policy.
    //
    // A matching "allow" rule at priority P-1 tells Chrome to ignore all
    // modifyHeaders rules from this extension with priority <= P-1 (the static
    // default, parent domains, or a dynamic rule when a session rule exists),
    // so only this rule's CSP at priority P is appended.
    toOverrideRule() {
        return {
            id: this.overrideId,
            action: { type: "allow" },
            condition: structuredClone(this.condition),
            priority: this.priority - kOverridePriorityOffset,
        };
    }

    toRules() {
        return [this.toOverrideRule(), this.toRule()];
    }
}

class Ruleset {
    resource;
    id;
    enabled;
    static #cache = new Map();

    constructor(resource) {
        this.resource = resource;
        this.id       = resource.id;
        this.enabled  = resource.enabled;
        this.url      = chrome.runtime.getURL(resource.path);
    }

    get json() {
        return Ruleset.#cache.get(this.url)?.json;
    }

    async isEnabled() {
        let rulesets = await chrome.declarativeNetRequest.getEnabledRulesets();
        this.enabled = rulesets.includes(this.id);
        return this.enabled;
    }

    isRequired() {
        return this.id == "base";
    }

    async #load() {
        if (this.json)
            return true;

        try {
            const response = await fetch(this.url);

            if (response.ok != true)
                return false;

            let data = await response.json();

            Ruleset.#cache.set(this.url, { json: data });
            return true;
        } catch (e) {
            return false;
        }
    }

    async toPolicy()
    {
        // Return the parsed policy immediately if it's already in the shared cache.
        let cached = Ruleset.#cache.get(this.url);
        if (cached?.policy)
            return cached.policy;

        let policy = new Policy();

        // Populate JSON in cache; return a blank policy if the fetch fails.
        if (!await this.#load())
            return policy;

        const csp = this.json
            .flatMap(rule => rule.action?.responseHeaders ?? [])
            .find(r => r.header == "Content-Security-Policy");

        // Parse and store the policy object in the cache if it's an 'append' operation.
        if (csp?.operation == "append") {
            policy.fromHeader(csp.value);
        }

        Ruleset.#cache.set(this.url, { json: this.json, policy });
        return policy;
    }
}

// This class will manage rules, and handle translating them between different forms.
export default class Rules {
    #staticRulesets;
    #id;
    #rules;
    #exempt;

    // Map the defaultpolicy option slider to the static ruleset it enables.
    static PolicyRulesets = [
        "permissive",   // 0: Off
        "firstparty",   // 1: First Party
        "sandbox-lite", // 2: Sandbox (scripts + forms)
        "sandbox",      // 3: Sandbox
        "strict",       // 4: Strict
    ];

    constructor() {
        this.#id = 0;
    }

    async applyDefaultPolicy(level) {
        let ruleset = Rules.PolicyRulesets[level];
        await this.setEnabledRulesets(ruleset ? [ruleset] : []);
    }

    async init() {
        const [dynamic, session] = await Promise.all([
            chrome.declarativeNetRequest.getDynamicRules(),
            chrome.declarativeNetRequest.getSessionRules()
        ]);

        this.#rules = new Map();
        this.#exempt = new Map();

        let dynamicOverrides = new Map(
            dynamic.filter(r => r.action.type === "allow" && r.condition.urlFilter)
                .map(r => [r.condition.urlFilter, r.id])
        );
        let sessionOverrides = new Map(
            session.filter(r => r.action.type === "allow" && r.condition.urlFilter)
                .map(r => [r.condition.urlFilter, r.id])
        );

        dynamic.filter(r => r.action.type === "modifyHeaders" && r.condition.urlFilter)
            .forEach(r => this.#setRule(new Rule(r, false, dynamicOverrides.get(r.condition.urlFilter))));
        session.filter(r => r.action.type === "modifyHeaders" && r.condition.urlFilter)
            .forEach(r => this.#setRule(new Rule(r, true, sessionOverrides.get(r.condition.urlFilter))));
        session.filter(r => r.condition.tabIds)
            .forEach(r => r.condition.tabIds.forEach(t => this.#exempt.set(t, r.id)));

        // Chrome's API doesn't list disabled rulesets, so enumerate them from the manifest.
        this.#staticRulesets ??= chrome.runtime.getManifest()
            .declarative_net_request.rule_resources
            .map(resource => new Ruleset(resource));

        for (let ruleset of this.#staticRulesets) {
            // Sync current state and probe internal rule IDs.
            await ruleset.isEnabled();
            await ruleset.toPolicy();
        }

        // Collect all live rule IDs across both buckets (including overrides and exemptions).
        let dynamicAndSessionIds = [
            ...dynamic.map(r => r.id),
            ...session.map(r => r.id),
        ];

        // Find the next available id to assign to new rules.
        this.#id = Math.max(0, ...dynamicAndSessionIds);
    }

    #setRule(rule) {
        let entry = this.#rules.get(rule.host) || {};
        if (rule.isSession) {
            entry.session = rule;
        } else {
            entry.dynamic = rule;
        }
        this.#rules.set(rule.host, entry);
    }

    #deleteRule(rule) {
        let entry = this.#rules.get(rule.host);
        if (!entry) return;

        if (rule.isSession) {
            delete entry.session;
        } else {
            delete entry.dynamic;
        }

        // No rules remain for this host, delete the Map entry.
        if (!entry.session && !entry.dynamic) {
            this.#rules.delete(rule.host);
        }
    }

    #getNextId() {
        return ++this.#id;
    }

    // Every panel has its own Rules instance and id counter, so changes to
    // dNR rules are serialized across all extension pages with a shared lock.
    // The mirror is resynced inside the lock, so new ids can't collide with
    // rules another panel just added, and removed ids can't be stale.
    #exclusive(fn) {
        return callWithLock("dnr", async () => {
            await this.init();
            return fn();
        });
    }

    addSessionRule(hostName, rulePolicy) {
        return this.#exclusive(() => this.#addSessionRule(hostName, rulePolicy));
    }

    abandonSessionRulesForHost(hostName) {
        return this.#exclusive(() => this.#abandonSessionRulesForHost(hostName));
    }

    commitSessionRulesForHost(hostName) {
        return this.#exclusive(() => this.#commitSessionRulesForHost(hostName));
    }

    uncommitDynamicRulesForHost(hostName) {
        return this.#exclusive(() => this.#uncommitDynamicRulesForHost(hostName));
    }

    resetHostRules(hostName) {
        return this.#exclusive(() => this.#resetHostRules(hostName));
    }

    delRule(rule) {
        return this.#exclusive(() => this.#delRule(rule));
    }

    replaceAllRules(session, dynamic) {
        return this.#exclusive(() => this.#replaceAllRules(session, dynamic));
    }

    pushToCloud() {
        return this.#exclusive(() => this.#pushToCloud());
    }

    pullFromCloud() {
        return this.#exclusive(() => this.#pullFromCloud());
    }

    addTabExemption(tabId) {
        return this.#exclusive(() => this.#addTabExemption(tabId));
    }

    delTabExemption(tabId) {
        return this.#exclusive(() => this.#delTabExemption(tabId));
    }

    // Wrap dNR mutation APIs so every change broadcasts NOTIFY_RULES to
    // sidepanels in other windows (their `#rules` mirror is now stale).
    async #updateSessionRules(opts) {
        await chrome.declarativeNetRequest.updateSessionRules(opts);
        chrome.runtime.sendMessage({ command: MessageTypes.NOTIFY_RULES }).catch(() => {});
    }

    async #updateDynamicRules(opts) {
        await chrome.declarativeNetRequest.updateDynamicRules(opts);
        chrome.runtime.sendMessage({ command: MessageTypes.NOTIFY_RULES }).catch(() => {});
    }

    async #updateEnabledRulesets(opts) {
        await chrome.declarativeNetRequest.updateEnabledRulesets(opts);
        chrome.runtime.sendMessage({ command: MessageTypes.NOTIFY_RULES }).catch(() => {});
    }

    #findSessionForHost(hostName) {
        return this.#rules.get(hostName)?.session;
    }

    #findDynamicForHost(hostName) {
        return this.#rules.get(hostName)?.dynamic;
    }

    // Policy from the single enabled (non-required) static ruleset. Copied so
    // callers (e.g. setCurrentRules) can mutate it without corrupting the cache.
    async getDefaultPolicy() {
        let policy = new Policy();
        let ruleset = this.#staticRulesets.find(r => r.enabled && !r.isRequired());

        if (ruleset) {
            let p = await ruleset.toPolicy();
            Object.assign(policy.directives, structuredClone(p.directives));
        }
        return policy;
    }

    // Policy for a single static ruleset by id (e.g. "firstparty"), whether or
    // not it's currently enabled. Read-only: returns the shared cached policy.
    async getRulesetPolicy(id) {
        let ruleset = this.#staticRulesets.find(r => r.id == id);
        if (!ruleset)
            return new Policy();
        return ruleset.toPolicy();
    }

    // If we point our report-uri at our web_accessible_resource, there is no
    // console noise when we block requests. However, if workers are allowed,
    // we have to switch to a different solution, those requests are handled
    // differently by Chromium and cannot be intercepted.
    // The problem is WorkerScriptFetcher::CreateFactoryBundle doesn't wrap non-network
    // scheme factories (i.e. chrome-extension://) in
    // WebRequestProxyingURLLoaderFactory, and
    // ServiceWorkerNetworkProviderForFrame intercepts https: subresources. The solution
    // is to use a wss: report-uri instead, which should bypass SW interception
    // while still reaching webRequest.
    #setReportUri(policy) {
        delete policy.directives["report-to"];
        policy.directives["report-uri"] = [
            policy.isDirectiveDisabled("worker-src")
                ? chrome.runtime.getURL("csp-report")
                : "wss://_matrix3.internal/csp-report"
        ];
    }

    // Install rulePolicy as a session (allow, append) rule pair for hostName,
    // replacing any prior session pair. Any existing dynamic pair stays put at
    // its lower tier offset (10L + 1..2 vs session's 10L + 3..4) so the session
    // pair suppresses it at runtime, and Abandon can delete the session pair to
    // restore the dynamic pair.
    async #addSessionRule(hostName, rulePolicy) {
        let rule = new Rule(null, true);
        let oldSession = this.#findSessionForHost(hostName);

        this.#setReportUri(rulePolicy);

        rule.host = hostName;
        rule.fromPolicy(rulePolicy);

        // Reuse the old session rule's IDs so toggling checkboxes updates it in place.
        if (oldSession?.id && oldSession?.overrideId) {
            rule.id = oldSession.id;
            rule.overrideId = oldSession.overrideId;
        } else {
            rule.overrideId = this.#getNextId();
            rule.id = this.#getNextId();
        }

        await this.#updateSessionRules({
            removeRuleIds: oldSession ? oldSession.ids : [],
            addRules: rule.toRules(),
        });

        this.#setRule(rule);
    }

    // Delete the session rule for hostName (if any); any dynamic rule stays put.
    async #abandonSessionRulesForHost(hostName) {
        let rule = this.#findSessionForHost(hostName);

        if (!rule) {
            console.error("rules", `attempted to abandon non-existent session rule for ${hostName}`);
            return;
        }

        await this.#delSessionRule(rule);
    }

    async #delRule(rule) {
        // The caller's rule may predate the resync in #exclusive (e.g. a row
        // in the Rules panel), so delete whatever rule exists now for its
        // host and tier.
        if (rule?.isSession)
            rule = this.#findSessionForHost(rule.host);
        else if (rule)
            rule = this.#findDynamicForHost(rule.host);

        if (!rule) {
            console.debug("rules", `attempted to delete null rule`);
        } else if (rule.isSession) {
            await this.#delSessionRule(rule);
        } else {
            await this.#delDynamicRule(rule);
        }
    }

    async #delSessionRule(rule) {
        await this.#updateSessionRules({
            removeRuleIds: rule.ids,
            addRules: []
        });
        this.#deleteRule(rule);
    }

    async #delDynamicRule(rule) {
        await this.#updateDynamicRules({
            removeRuleIds: rule.ids,
            addRules: []
        });
        this.#deleteRule(rule);
    }

    // Wipe every session and dynamic rule (two batched API calls). Queries
    // Chrome directly so it doesn't need a fresh init(). Static rulesets
    // are left alone.
    async resetAllRules() {
        await this.replaceAllRules([], []);
    }

    // Bulk swap or partial replacement. Re-inits since imported ids are arbitrary.
    // If an argument is null, the existing rules in that bucket are preserved.
    async #replaceAllRules(session = [], dynamic = []) {
        let oldSession = await chrome.declarativeNetRequest.getSessionRules();
        let oldDynamic = await chrome.declarativeNetRequest.getDynamicRules();

        session ??= oldSession;
        dynamic ??= oldDynamic;

        // Snapshot the live ids before reassigning -- a preserved bucket aliases the old array.
        let removeSessionIds = oldSession.map(r => r.id);
        let removeDynamicIds = oldDynamic.map(r => r.id);

        // Reset our internal ID counter and re-assign IDs to all incoming rules
        // to guarantee a collision-free set for the atomic swap.
        this.#id = 0;

        let buildPair = (rawRule, isSession) => {
            let rule = new Rule(rawRule, isSession, this.#getNextId());
            let policy = rule.policy;
            this.#setReportUri(policy);
            rule.fromPolicy(policy);
            rule.id = this.#getNextId();
            return rule.toRules();
        };

        let sessionHostRules = new Map();
        let sessionExemptRules = [];
        for (let r of session) {
            if (r.condition?.tabIds) {
                let exempt = structuredClone(r);
                exempt.id = this.#getNextId();
                exempt.priority = kBypassPriority;
                delete exempt.condition.resourceTypes;
                exempt.condition.excludedResourceTypes = [...kExcludedResourceTypes];
                sessionExemptRules.push(exempt);
            } else if (r.action?.type === "modifyHeaders" && r.condition?.urlFilter) {
                sessionHostRules.set(r.condition.urlFilter, r);
            }
        }

        let dynamicHostRules = new Map();
        for (let r of dynamic) {
            if (r.action?.type === "modifyHeaders" && r.condition?.urlFilter) {
                dynamicHostRules.set(r.condition.urlFilter, r);
            }
        }

        let addSession = [
            ...Array.from(sessionHostRules.values(), r => buildPair(r, true)).flat(),
            ...sessionExemptRules,
        ];
        let addDynamic = Array.from(dynamicHostRules.values(), r => buildPair(r, false)).flat();

        try {
            await this.#updateSessionRules({
                removeRuleIds: removeSessionIds,
                addRules: addSession,
            });
            await this.#updateDynamicRules({
                removeRuleIds: removeDynamicIds,
                addRules: addDynamic,
            });
        } finally {
            // Refresh the mirror even on a partial failure (e.g. dNR rule cap).
            await this.init();
        }
    }

    // Record the set of cloud keys this device has locally synced. Comparing
    // against this common ancestor lets the next Push or Pull distinguish
    // "deleted on one side" (was in synced, now missing) from "not yet synced
    // to the other side" (never in synced).
    async #getSyncedBaseline() {
        let { synced } = await chrome.storage.local.get("synced");
        return {
            rules: new Set(synced?.rules ?? []),
            groups: synced?.groups ?? {},
        };
    }

    async #saveSyncedBaseline(ruleHosts, groups) {
        await chrome.storage.local.set({
            synced: { rules: [...new Set(ruleHosts)], groups },
        });
    }

    // Three-way merge of a group's origin map against `base` (the origin map
    // at last sync): keep `theirs` unless deleted in `ours`, and apply `ours`
    // unless `ours` is unchanged from `base` while `theirs` changed.
    #mergeGroupOrigins(ours = {}, theirs = {}, base = {}) {
        let sameDirs = (a, b) => a && b && a.length === b.length && a.every(v => b.includes(v));
        let merged = {};

        for (let [origin, dirs] of Object.entries(theirs)) {
            if (origin in ours || !(origin in base))
                merged[origin] = dirs;
        }
        for (let [origin, dirs] of Object.entries(ours)) {
            if (!(origin in base) || !sameDirs(dirs, base[origin]))
                merged[origin] = dirs;
        }
        return merged;
    }

    // These two routines don't actually do any cloud stuff, chrome syncs the
    // options object automatically.
    // We're limited with how much data we're allowed to store in there, so keep
    // the representation simple.
    async #pushToCloud() {
        let dynamic = this.getRules().filter(r => !r.isSession);
        let groups = structuredClone(await Options.getGroups());
        let storage = await chrome.storage.sync.get(null);
        let synced = await this.#getSyncedBaseline();
        let toSet = {};
        let stale = [];

        for (let rule of dynamic) {
            let policy = rule.policy;

            // report-uri is per-device; pull re-derives it, so don't store it.
            delete policy.directives["report-uri"];
            delete policy.directives["report-to"];

            toSet[`rule:${rule.host}`] = { policy: policy.toHeader() };
        }

        for (let [name, group] of Object.entries(groups)) {
            let key = `group:${name}`;
            toSet[key] = this.#mergeGroupOrigins(group, storage[key], synced.groups[name]);
        }

        // Only remove cloud rules or groups that existed at our last sync and
        // were since deleted locally; leave unpulled items from other devices alone.
        for (let key of Object.keys(storage)) {
            let name = key.slice(key.indexOf(":") + 1);
            if (key.startsWith("rule:") && !(key in toSet) && synced.rules.has(name))
                stale.push(key);
            if (key.startsWith("group:") && !(key in toSet) && name in synced.groups)
                stale.push(key);
        }

        await chrome.storage.sync.set(toSet);
        await chrome.storage.sync.remove(stale);

        // Record what we have locally; remote-only items left in cloud remain
        // outside our baseline until pullFromCloud() imports them.
        await this.#saveSyncedBaseline(dynamic.map(r => r.host), groups);

        // Record this push so the panel can show when we last synced.
        await chrome.storage.sync.set({ [kLastPushKey]: { time: Date.now() } });

        return dynamic.length;
    }

    async getCloudTime() {
        let storage = await chrome.storage.sync.get(kLastPushKey);
        return storage[kLastPushKey]?.time ?? null;
    }

    async getCloudRules() {
        let storage = await chrome.storage.sync.get(null);
        return Object.keys(storage)
            .filter(k => k.startsWith("rule:"))
            .map(k => k.slice(k.indexOf(":") + 1));
    }

    async getCloudGroups() {
        let storage = await chrome.storage.sync.get(null);
        return Object.keys(storage)
            .filter(k => k.startsWith("group:"))
            .map(k => k.slice(k.indexOf(":") + 1));
    }

    async #pullFromCloud() {
        let mergedMap = new Map();
        let groups = await Options.getGroups();
        let storage = await chrome.storage.sync.get(null);
        let synced = await this.#getSyncedBaseline();
        let cloudRules = Object.keys(storage).filter(k => k.startsWith("rule:"));
        let cloudGroups = Object.keys(storage).filter(k => k.startsWith("group:"));

        // Keep local rules unless they were in our last sync and removed from cloud.
        for (let r of this.getRules().filter(r => !r.isSession)) {
            if (`rule:${r.host}` in storage || !synced.rules.has(r.host))
                mergedMap.set(r.host, r.toRule());
        }

        for (let key of cloudRules) {
            let rule = new Rule();

            // key is the storage key, so strip the "rule:" prefix.
            rule.host = key.slice(key.indexOf(":") + 1);
            rule.fromPolicyString(storage[key].policy);
            mergedMap.set(rule.host, rule.toRule());
        }

        await this.#replaceAllRules(null, Array.from(mergedMap.values()));

        // Drop local groups that existed at last sync and were deleted in cloud.
        for (let name of Object.keys(groups)) {
            if (name !== "Ignore" && !(`group:${name}` in storage) && name in synced.groups)
                delete groups[name];
        }

        let pulledGroups = {};
        for (let key of cloudGroups) {
            let name = key.slice(key.indexOf(":") + 1);
            pulledGroups[name] = storage[key];
            let merged = this.#mergeGroupOrigins(storage[key], groups[name], synced.groups[name]);
            // Don't recreate a locally deleted group as `{}` unless cloud has new edits.
            if (name in groups || !(name in synced.groups) || Object.keys(merged).length > 0)
                groups[name] = merged;
        }

        await Options.saveGroups();

        // Record only what came from cloud; local-only items remain outside
        // our baseline until pushToCloud() uploads them.
        await this.#saveSyncedBaseline(cloudRules.map(k => k.slice(k.indexOf(":") + 1)), pulledGroups);
        return cloudRules.length;
    }

    // Remove every session and dynamic rule for this host.
    async #resetHostRules(hostName) {
        let session = this.#findSessionForHost(hostName);
        let dynamic = this.#findDynamicForHost(hostName);

        if (session) await this.#delSessionRule(session);
        if (dynamic) await this.#delDynamicRule(dynamic);
    }

    // Demote the host's dynamic rule into a session rule (inverse of Commit).
    // No-op if there's no dynamic rule, or if a session rule already exists
    // for this host -- the user should commit or abandon that first.
    async #uncommitDynamicRulesForHost(hostName) {
        let rule = this.#findDynamicForHost(hostName);
        let session = this.#findSessionForHost(hostName);
        if (!rule || session)
            return;
        let next = new Rule(rule.toRule(), true);
        next.overrideId = this.#getNextId();
        next.id = this.#getNextId();
        await this.#updateSessionRules({
            removeRuleIds: [],
            addRules: next.toRules(),
        });
        try {
            await this.#updateDynamicRules({
                removeRuleIds: rule.ids,
                addRules: [],
            });
        } catch (e) {
            await this.#updateSessionRules({
                removeRuleIds: next.ids,
                addRules: [],
            });
            throw e;
        }
        this.#deleteRule(rule);
        this.#setRule(next);
    }

    // Promote the host's session rule into a dynamic rule, replacing any
    // existing dynamic. Priority is computed deterministically for the dynamic tier.
    async #commitSessionRulesForHost(hostName) {
        let rule = this.#findSessionForHost(hostName);
        let prev = this.#findDynamicForHost(hostName);
        if (!rule)
            return;
        let next = new Rule(rule.toRule(), false);
        next.overrideId = this.#getNextId();
        next.id = this.#getNextId();
        await this.#updateDynamicRules({
            removeRuleIds: prev ? prev.ids : [],
            addRules: next.toRules(),
        });
        this.#setRule(next);
        await this.#updateSessionRules({
            removeRuleIds: rule.ids,
            addRules: [],
        });
        this.#deleteRule(rule);
    }

    // Rule for matching host (or its closest ancestor domain, since ||host^
    // rules match subdomains), preferring session over dynamic at each level.
    getHostRule(hostName) {
        let labels = hostName ? hostName.split(".") : [];

        while (labels.length) {
            let host = labels.join(".");
            let rule = this.#findSessionForHost(host) ?? this.#findDynamicForHost(host);
            if (rule)
                return rule;
            labels.shift();
        }
        return null;
    }

    getRules() {
        return Array.from(this.#rules.values()).flatMap(v => Object.values(v));
    }

    getAllStaticRules() {
        return this.#staticRulesets;
    }

    isTabExempt(tabId) {
        return this.#exempt?.has(tabId) ?? false;
    }

    async #addTabExemption(tabId) {
        if (!tabId || this.#exempt.has(tabId))
            return;

        let id = this.#getNextId();
        let rule = {
            id,
            priority: kBypassPriority,
            action: { type: "allow" },
            condition: {
                excludedResourceTypes: [...kExcludedResourceTypes],
                tabIds: [tabId],
            },
        };

        await this.#updateSessionRules({
            removeRuleIds: [],
            addRules: [rule],
        });

        this.#exempt.set(tabId, id);
    }

    async #delTabExemption(tabId) {
        let id = this.#exempt.get(tabId);
        if (!id)
            return;

        await this.#updateSessionRules({
            removeRuleIds: [id],
            addRules: [],
        });

        this.#exempt.delete(tabId);
    }

    // Enable exactly the named static rulesets (plus required ones); disable
    // every other non-required ruleset. One batched API call, atomic.
    async setEnabledRulesets(ids) {
        let wanted = new Set(ids);
        let enableRulesetIds = [];
        let disableRulesetIds = [];

        // Only include rulesets whose enabled state actually needs to flip.
        for (let r of this.#staticRulesets) {
            if (r.isRequired())
                continue;
            if (wanted.has(r.id) && !r.enabled)
                enableRulesetIds.push(r.id);
            else if (!wanted.has(r.id) && r.enabled)
                disableRulesetIds.push(r.id);
        }

        // Skip the NOTIFY_RULES broadcast if we know nothing changed.
        if (enableRulesetIds.length === 0 && disableRulesetIds.length === 0)
            return;

        await this.#updateEnabledRulesets({
            enableRulesetIds,
            disableRulesetIds,
        });

        for (let r of this.#staticRulesets)
            await r.isEnabled();
    }

}
