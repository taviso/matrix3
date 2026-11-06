import Policy from '/include/policy.js'
import { MessageTypes } from '/include/commands.js'

// dNR priorities are ordinal: bypass > session > dynamic > static.
const kStaticPriority  = 1;
const kDynamicPriority = 2;
const kSessionPriority = 3;
const kBypassPriority  = 4;

// Sync key recording when we last pushed rules.
const kLastPushKey = "meta:lastpush";

// A declarativeNetRequest rule (session or dynamic).
class Rule {
    id;
    priority;
    isSession;
    action = {};
    condition = {};

    // rule is a raw JSON DNR rule object from chrome.storage or dNR APIs.
    constructor(rule, session = false)
    {
        this.id = rule?.id;
        this.action.type = "modifyHeaders";
        this.action.responseHeaders = [{
            header: "Content-Security-Policy",
            operation: "set",
        }];
        this.condition.resourceTypes = [
            "main_frame", "sub_frame"
        ];
        this.condition.urlFilter = rule?.condition?.urlFilter;
        this.priority = rule?.priority;
        this.isSession = session;

        // Normalize the raw CSP value through Policy abstractions.
        this.fromPolicyString(rule?.action?.responseHeaders?.[0]?.value);
    };

    set host(host) {
        this.condition.urlFilter = "||" + host + "^";
    }

    get host() {
        return this.condition.urlFilter?.slice(2, -1);
    }

    set tabId(tabId) {
        this.condition.tabIds = [tabId];
    }

    get tabId() {
        return this.condition.tabIds?.[0];
    }

    get policy() {
        return this.toPolicy();
    }

    toPolicy() {
        let csp = new Policy();
        return csp.fromHeader(this.action.responseHeaders[0].value);
    }

    fromPolicy(policy) {
        this.action.responseHeaders[0].value = policy.toHeader();
    }

    fromPolicyString(headerString) {
        this.fromPolicy(new Policy().fromHeader(headerString));
    }

    toRule() {
        return {
            id: this.id,
            action: this.action,
            condition: this.condition,
            priority: this.priority,
        };
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

            let [data] = await response.json();

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

        const csp = this.json.action.responseHeaders?.find(r => r.header == "Content-Security-Policy");

        // Parse and store the policy object in the cache if it's a 'set' operation.
        if (csp?.operation == "set") {
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

        dynamic.forEach(r => this.#setRule(new Rule(r)));
        session.filter(r => r.condition.urlFilter)
            .forEach(r => this.#setRule(new Rule(r, true)));
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

        // Collect all the rule ids currently refined.
        let dynamicAndSessionIds = [
            ...this.getRules().map(r => r.id),
            ...this.#exempt.values(),
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

    // Install rulePolicy as a session rule for hostName, replacing any prior
    // session. Any existing dynamic stays put; the session's priority is
    // bumped above it so the session wins at runtime, and Abandon can then
    // delete the session to restore the dynamic.
    async addSessionRule(hostName, rulePolicy) {
        let rule = new Rule(null, true);
        let oldSession = this.#findSessionForHost(hostName);
        let oldDynamic = this.#findDynamicForHost(hostName);

        // Point report-uri at our extension's WAR to avoid ERR_BLOCKED_BY_CLIENT errors.
        rulePolicy.directives["report-uri"] = [chrome.runtime.getURL("csp-report")];

        rule.host = hostName;
        rule.priority = kDynamicPriority;
        rule.fromPolicy(rulePolicy);

        // The new session rule should take priority over any old dynamic rule, the
        // user can test it and then commit it.
        if (oldDynamic)
            rule.priority = oldDynamic.priority + 1;

        // Reuse the old session rule's ID so toggling checkboxes updates it in place.
        if (oldSession)
            rule.id = oldSession.id;
        else
            rule.id = this.#getNextId();

        await this.#updateSessionRules({
            removeRuleIds: oldSession ? [oldSession.id] : [],
            addRules: [ rule.toRule() ],
        });

        this.#setRule(rule);
    }

    // Delete the session rule for hostName (if any); any dynamic rule stays put.
    async abandonSessionRulesForHost(hostName) {
        let rule = this.#findSessionForHost(hostName);

        if (!rule) {
            console.error("rules", `attempted to abandon non-existent session rule for ${hostName}`);
            return;
        }

        await this.delSessionRule(rule);
    }

    async delRule(rule) {
        if (!rule) {
            console.debug("rules", `attempted to delete null rule`);
        } else if (rule.isSession) {
            await this.delSessionRule(rule);
        } else {
            await this.delDynamicRule(rule);
        }
    }

    async delSessionRule(rule) {
        await this.#updateSessionRules({
            removeRuleIds: [rule.id],
            addRules: []
        });
        this.#deleteRule(rule);
    }

    async delDynamicRule(rule) {
        await this.#updateDynamicRules({
            removeRuleIds: [rule.id],
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
    async replaceAllRules(session = [], dynamic = []) {
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
        session.forEach(r => r.id = this.#getNextId());
        dynamic.forEach(r => r.id = this.#getNextId());

        try {
            await this.#updateSessionRules({
                removeRuleIds: removeSessionIds,
                addRules: session,
            });
            await this.#updateDynamicRules({
                removeRuleIds: removeDynamicIds,
                addRules: dynamic,
            });
        } finally {
            // Refresh the mirror even on a partial failure (e.g. dNR rule cap).
            await this.init();
        }
    }

    // These two routines don't actually do any cloud stuff, chrome syncs the
    // options object automatically.
    // We're limited with how much data we're allowed to store in there, so keep
    // the representation simple.
    async pushToCloud() {
        let dynamic = this.getRules().filter(r => !r.isSession);
        let storage = await chrome.storage.sync.get(null);
        let toSet = {};

        for (let rule of dynamic) {
            let policy = rule.policy;

            // report-uri is per-device; pull re-derives it, so don't store it.
            delete policy.directives["report-uri"];

            toSet[`rule:${rule.host}`] = { policy: policy.toHeader() };
        }

        // Push clobbers, so drop any cloud rule the local set no longer has.
        let stale = [];

        for (let key of Object.keys(storage)) {
            if (key.startsWith("rule:") && !(key in toSet))
                stale.push(key);
        }

        await chrome.storage.sync.remove(stale);
        await chrome.storage.sync.set(toSet);

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
            .map(k => k.slice(5));
    }

    async pullFromCloud() {
        let mergedMap = new Map();
        let storage = await chrome.storage.sync.get(null);
        let cloudRules = Object.keys(storage).filter(k => k.startsWith("rule:"));

        for (let r of this.getRules().filter(r => !r.isSession)) {
            mergedMap.set(r.host, r.toRule());
        }

        for (let host of cloudRules) {
            let rule = new Rule();
            let policy = new Policy().fromHeader(storage[host].policy);

            // Re-derive report-uri for this device rather than trusting storage.
            policy.directives["report-uri"] = [chrome.runtime.getURL("csp-report")];

            // host is the storage key, so remove the "rule:" prefix.
            rule.host = host.slice(5);
            rule.priority = kDynamicPriority;
            rule.fromPolicy(policy);
            mergedMap.set(rule.host, rule.toRule());
        }

        await this.replaceAllRules(null, Array.from(mergedMap.values()));
        return cloudRules.length;
    }

    // Remove every session and dynamic rule for this host.
    async resetHostRules(hostName) {
        let session = this.#findSessionForHost(hostName);
        let dynamic = this.#findDynamicForHost(hostName);

        if (session) await this.delSessionRule(session);
        if (dynamic) await this.delDynamicRule(dynamic);
    }

    // Demote the host's dynamic rule into a session rule (inverse of Commit).
    // No-op if there's no dynamic rule, or if a session rule already exists
    // for this host -- the user should commit or abandon that first.
    async uncommitDynamicRulesForHost(hostName) {
        let rule = this.#findDynamicForHost(hostName);
        let session = this.#findSessionForHost(hostName);
        if (!rule || session)
            return;
        await this.#updateSessionRules({
            removeRuleIds: [],
            addRules: [rule.toRule()],
        });
        await this.#updateDynamicRules({
            removeRuleIds: [rule.id],
            addRules: [],
        });
        this.#deleteRule(rule);
        rule.isSession = true;
        this.#setRule(rule);
    }

    // Promote the host's session rule into a dynamic rule, replacing any
    // existing dynamic. Priority is demoted back to the prior dynamic's
    // level so commits don't drift priorities upward.
    async commitSessionRulesForHost(hostName) {
        let rule = this.#findSessionForHost(hostName);
        let prev = this.#findDynamicForHost(hostName);
        if (!rule)
            return;
        if (prev)
            rule.priority = prev.priority;
        await this.#updateDynamicRules({
            removeRuleIds: prev ? [prev.id] : [],
            addRules: [rule.toRule()],
        });
        await this.#updateSessionRules({
            removeRuleIds: [rule.id],
            addRules: [],
        });
        this.#deleteRule(rule);
        rule.isSession = false;
        // #setRule overwrites entry.dynamic; an explicit #deleteRule(prev)
        // afterwards would clobber the rule we just set (same host).
        this.#setRule(rule);
    }

    // Rule for matching host, preferring session over dynamic.
    getHostRule(hostName) {
        return this.#findSessionForHost(hostName) ?? this.#findDynamicForHost(hostName);
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

    async addTabExemption(tabId) {
        if (!tabId || this.#exempt.has(tabId))
            return;

        let rule = new Rule(null, true);
        rule.id = this.#getNextId();
        rule.priority = kBypassPriority;
        rule.action = { type: "allow" };
        rule.tabId = tabId;

        await this.#updateSessionRules({
            removeRuleIds: [],
            addRules: [rule.toRule()],
        });

        this.#exempt.set(tabId, rule.id);
    }

    async delTabExemption(tabId) {
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
