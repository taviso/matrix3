import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import * as psl from '/include/psl.js'
import Options from '/include/options.js'
import Policy from '/include/policy.js'
import { MessageTypes } from '/include/commands.js'

let RulesManager = sidepanel.RulesManager;
let groups = await Options.getGroups();

// Attach tooltips to the static sandbox checkboxes.
document.querySelectorAll("td input.sandbox").forEach(box => {
    box.title = sidepanel.helpData.sandbox[box.id] ?? "";
});

// Populate the source directive tables from the shared template.
document.querySelectorAll("table.sources").forEach(table => {
    table.append(document.getElementById("sources-template").content.cloneNode(true));
});

const directivesTable = document.querySelector("table#sources")
const sandboxTable = document.querySelector("table#sandbox")
const serverTable = document.querySelector("table#serversources")

const originList = document.querySelector("div#frames")
const unregistersw = document.querySelector("button.unregistersw")
unregistersw.remove();

Object.defineProperties(originList, {
    value: {
        get() { return this.querySelector('button.active')?.dataset.value ?? ''; },
        set(v) {
            this.querySelectorAll('button').forEach(b => b.classList.remove('active'));
            this.querySelector(`button[data-value="${v}"]`)?.classList.add('active');
        }
    },
    protocol: {
        get() { return this.querySelector('button.active')?.dataset.protocol; }
    }
})
const headerList = document.querySelector("textarea#servercsp")

let currentServerPolicies = [];

// User's last manual origin selection. Sticks across reloads even if a partial
// frame list temporarily falls back to the top domain.
let userOrigin;

// Clear Service Workers and caches for all origins under the given scope.
async function unregisterServiceWorker(domain) {
    let origins = await chrome.runtime.sendMessage({
        command: MessageTypes.DEL_WORKER,
           data: { domain }
    }).catch(() => []) ?? [];
    if (!origins.length)
        return;
    await chrome.browsingData.remove(
        { origins },
        { cache: true, cacheStorage: true, serviceWorkers: true }
    ).catch(e => console.warn("report", `failed to clear ${domain} browsing data`, e));
}

// Handle the main report buttons.
document.body.addEventListener('click', async (e) => {
    const host = e.target.parentElement?.dataset.value ?? originList.value;

    if (e.target.tagName !== 'BUTTON') return;

    switch (e.target.id || e.target.className) {
        case 'commit':
            await RulesManager.commitSessionRulesForHost(host);
            break;
        case 'reset':
            if (!await utils.confirmAction(`Remove all session and dynamic rules for ${host}?`)) return;
            await RulesManager.resetHostRules(host);
            break;
        case 'unregistersw':
            if (!await utils.confirmAction(`Unregister Service Worker and clear cache for ${host}?`)) return;
            await unregisterServiceWorker(host);
            break;
        case 'abandon':
            if (!await utils.confirmAction(`Discard session changes for ${host}?`)) return;
            await RulesManager.abandonSessionRulesForHost(host);
            break;
        case 'uncommit':
            await RulesManager.uncommitDynamicRulesForHost(host);
            break;
        case 'disable': {
            let tab = await sidepanel.getActiveTab();
            await RulesManager.addTabExemption(tab?.id);
            break;
        }
        case 'resume': {
            let tab = await sidepanel.getActiveTab();
            await RulesManager.delTabExemption(tab?.id);
            break;
        }
        case 'reload':
            await chrome.tabs.reload(undefined, { bypassCache: e.shiftKey });
            return;
        default:
            return;
    }

    updateReport();
});

// The server policy buttons.
document.getElementById('accept').addEventListener("click", () => {
    utils.setCheckboxes(directivesTable.querySelectorAll("td input[type=checkbox]"), false);
    resetSandboxDirectives();
    applyServerPolicy();
});

document.getElementById('merge').addEventListener("click", applyServerPolicy);

function applyServerSources() {
    let srcs = utils.getTableRowProps(serverTable, "textContent");
    let dirs = utils.getTableColProps(serverTable, "id");

    // Drop the row-title column id.
    dirs.shift();

    for (let src of srcs) {
        let target = Policy.importableSource(src);
        if (!target)
            continue;
        for (let dir of dirs) {
            if (!getSourceCheckboxState(src, dir, serverTable.tBodies[0]))
                continue;
            // In a server CSP, 'nonce-...' and 'strict-dynamic' in script-src
            // also authorize external <script nonce="..." src="..."> elements,
            // whereas 'unsafe-inline' only permits inline blocks. Also check
            // 'self' for script-src so same-origin nonced scripts can load.
            let targets = (dir === "script-src" && Policy.isNonceOrStrictDynamic(src))
                ? [target, "'self'"]
                : [target];
            for (let t of targets) {
                let box = findCheckbox(t, dir, true);
                if (!box)
                    continue;
                box.checked = true;
                enforceNoneLeader(box);
            }
        }
    }

    utils.sortTable(directivesTable, compareSourceRows);
}

function applyServerPolicy() {
    applyServerSources();
    applyServerSandbox();
    setCurrentRules(originList.value);
}

function enableSandbox(features) {
    document.querySelector("input#sandbox-enabled").checked = true;
    for (let id of features) {
        let box = document.getElementById(id);
        if (box?.classList.contains("allow"))
            box.checked = true;
    }
}

function applyServerSandbox() {
    for (let policy of currentServerPolicies) {
        if (policy.directives.sandbox)
            enableSandbox(policy.directives.sandbox);
    }
}

// Apply the selected group's sources and checked directives to the table.
function applyTrustGroup() {
    let name = document.getElementById('trustgroup').value;
    let group;

    if (!name)
        return;

    group = groups?.[name] ?? {};

    for (let [origin, dirs] of Object.entries(group)) {
        let target = Policy.importableSource(origin);
        if (!target)
            continue;
        addSourceCheckboxRow(target);
        for (let entry of dirs) {
            let enable = !entry.startsWith('!');
            let dir = enable ? entry : entry.slice(1);
            let box = findCheckbox(target, dir, true);
            if (!box)
                continue;
            box.checked = enable;
            enforceNoneLeader(box);
        }
    }

    utils.sortTable(directivesTable, compareSourceRows);
    setCurrentRules(originList.value);
}

document.getElementById('applygroup').addEventListener("click", applyTrustGroup);

originList.addEventListener("click", (e) => {
    let btn = e.target.closest("button");
    if (!btn?.dataset.value) return;
    userOrigin = btn.dataset.value;
    utils.callWithLock("report", async () => {
        originList.value = userOrigin;
        await refreshTable(originList.value);
        updateOriginScopeState();
    });
});

// 'none' must be alone in a CSP source list: checking 'none' clears the
// column, checking anything else clears 'none'.
function enforceNoneLeader(target) {
    let cell = target.closest("td");
    let table = target.closest("table");
    let noneRow = utils.findTableRow(table, "'none'");
    let col;
    let noneBox;
    let group;

    if (!target.checked)
        return;
    if (!cell || !noneRow)
        return;

    col = cell.cellIndex;
    noneBox = noneRow.cells[col].firstChild;
    group = Array.from(table.tBodies[0].rows, r => r.cells[col].firstChild);

    if (target === noneBox)
        utils.checkboxMutex(group, noneBox);
    else
        noneBox.checked = false;
}

directivesTable.addEventListener("change", (event) => {
    enforceNoneLeader(event.target);
    setCurrentRules(originList.value);
});
serverTable.addEventListener("change", (event) => {
    enforceNoneLeader(event.target);
    serverTable.dataset.dirty = "true";
});
sandboxTable.addEventListener("change", async (event) => {
    let host = originList.value;
    if (event.target.id === "sandbox-enabled")
        await fallbackToFirstParty();
    setCurrentRules(host);
});

function resetSandboxDirectives()
{
    utils.setCheckboxes(document.querySelectorAll("td input.sandbox"), false);
}

function buildDefaultDirectivesFragment()
{
    let fragment = document.createDocumentFragment();

    // Add some default sources.
    addSourceCheckboxRow("'none'", fragment);
    addSourceCheckboxRow("'self'", fragment);
    addSourceCheckboxRow("'unsafe-eval'", fragment);
    addSourceCheckboxRow("'wasm-unsafe-eval'", fragment);
    addSourceCheckboxRow("'unsafe-inline'", fragment);
    addSourceCheckboxRow("'unsafe-hashes'", fragment);
    addSourceCheckboxRow("https:", fragment);
    addSourceCheckboxRow("http:", fragment);
    addSourceCheckboxRow("data:", fragment);
    addSourceCheckboxRow("blob:", fragment);

    return fragment;
}

// Add a row with the given source name, or return the existing row.
// Idempotent so callers can blindly re-add the same nonce/hash every refresh.
function addSourceCheckboxRow(source, container = directivesTable.tBodies[0])
{
    // Check if it already exists in the container (which might be a fragment)
    let existing = Array.from(container.children).find(r => r.cells[0]?.textContent === source);
    let cols = utils.getTableColProps(directivesTable, "id");
    let colNodes = directivesTable.querySelectorAll("colgroup col");
    let row;
    let title;

    if (existing)
        return existing;

    row = document.createElement("tr");
    title = document.createElement("th");

    title.append(utils.formatSource(source));
    title.title = source;
    row.appendChild(title);

    for (let i = 1; i < cols.length; i++) {
        let cell = row.insertCell(-1);
        let box = document.createElement("input");
        box.type = "checkbox";
        box.checked = false;
        box.className = "rule";
        box.title = sidepanel.getRuleTooltip(source, cols[i]);

        if (colNodes[i].classList.contains("advanced"))
            cell.classList.add("advanced");
        cell.appendChild(box);
    }

    container.appendChild(row);

    return row;
}

function findCheckbox(source, directive, autoAdd, container = directivesTable.tBodies[0])
{
    let cols = utils.getTableColProps(directivesTable, "id");
    let row = Array.from(container.children).find(r => r.cells[0]?.textContent === source);
    let colNum = cols.indexOf(directive);

    if (colNum == -1) {
        console.debug("report", `column for directive ${directive} does not exist`);
        return null;
    }
    if (!row && autoAdd) {
        console.debug("report", `source name ${source} is unknown, adding`);
        row = addSourceCheckboxRow(source, container);
    }

    return row?.cells[colNum].firstChild ?? null;
}

function setSourceCheckboxState(source, directive, state, className, container = directivesTable.tBodies[0])
{
    if (!source)
        return;
    let box = findCheckbox(source, directive, true, container);
    if (!box)
        return;
    box.checked = state;
    if (className)
        box.classList.add(className);
}

function setSourceCheckboxClass(source, directive, className, container = directivesTable.tBodies[0])
{
    let box = findCheckbox(source, directive, true, container);
    if (box)
        box.classList.add(className);
}

function getSourceCheckboxState(source, directive, container = directivesTable.tBodies[0])
{
    return findCheckbox(source, directive, false, container)?.checked;
}

// Seed the first-party policy when default-src is empty, so the CSP isn't
// implicitly wide-open. It's one step less strict than 'none', which is more
// convenient than a bare default-src. Skipped when sandbox is enabled.
async function fallbackToFirstParty(container = directivesTable.tBodies[0]) {
    let col;
    let boxes;
    let policy;
    let columns;

    if (document.querySelector("input#sandbox-enabled").checked)
        return;

    col = utils.getTableColProps(directivesTable, "id").indexOf("default-src");
    boxes = Array.from(container.children, r => r.cells[col].firstChild);

    if (boxes.some(b => b.checked))
        return;

    policy = await RulesManager.getRulesetPolicy("firstparty");
    columns = utils.getTableColProps(directivesTable, "id");

    for (let [directive, sources] of Object.entries(policy.directives)) {
        let dir = Policy.collapseDirective(directive);
        if (columns.includes(dir))
            sources.forEach(src => setSourceCheckboxState(Policy.importableSource(src), dir, true, undefined, container));
    }
}

// Sort sources alphabetically, but with nonce-* / sha*-* values at the end
// since they're noisy and rarely toggled.
function compareSourceRows(a, b) {
    let isHash = l => Policy.isNonceOrHash(l);
    let al = a.cells[0].textContent;
    let bl = b.cells[0].textContent;
    return (isHash(al) - isHash(bl)) || al.localeCompare(bl);
}

async function getCurrentRules(hostName, container)
{
    let rule = RulesManager.getHostRule(hostName);
    let columns = utils.getTableColProps(directivesTable, "id");
    let policy;
    let className;

    if (rule?.isSession)
        className = "session";
    else if (rule)
        className = "dynamic";

    if (rule)
        policy = rule.policy;
    else
        policy = await RulesManager.getDefaultPolicy();

    for (let directive in policy.directives) {
        let sources = policy.directives[directive];

        if (directive == "sandbox") {
            enableSandbox(sources);
            continue;
        }

        let dir = Policy.collapseDirective(directive);
        if (columns.includes(dir))
            sources.forEach(src => setSourceCheckboxState(Policy.importableSource(src), dir, true, className, container));
    }
}

function isIgnored(source, directive)
{
    let dirs = groups?.Ignore?.[source];
    if (dirs?.includes(`!${directive}`))
        return false;
    return dirs?.includes("default-src") || dirs?.includes(directive);
}

function setCurrentViolations(data, container)
{
    for (let directive in data) {
        let dir = Policy.collapseDirective(directive);
        for (let src of data[directive]) {
            if (isIgnored(src, dir))
                continue;
            setSourceCheckboxClass(src, dir, "violation", container);
        }
    }
}

function setCurrentRules(hostName)
{
    let row = directivesTable.tBodies[0].rows[0];
    let tab = sidepanel.getActiveTab();

    return utils.callWithLock("report", async () => {
        if (!row?.isConnected || hostName !== originList.value)
            return;

        tab = await tab;
        let srcs = utils.getTableRowProps(directivesTable, "textContent");
        let dirs = utils.getTableColProps(directivesTable, "id");
        let policy = new Policy();

        // Drop the row-title column id.
        dirs.shift();

        for (let dir of dirs) {
            let activeSources = srcs.filter(src => getSourceCheckboxState(src, dir));

            if (activeSources.length === 0)
                continue;

            if (activeSources.includes("'none'")) {
                policy.directives[dir] = ["'none'"];
                continue;
            }

            policy.directives[dir] ??= [];
            for (let src of activeSources) {
                if (!policy.directives[dir].includes(src)) {
                    policy.directives[dir].push(src);
                }
            }
        }

        // Sandbox policies.
        let sbx = document.querySelector("input#sandbox-enabled");
        let features = Array.from(document.querySelectorAll("td input.sandbox.allow:checked"), f => f.id);

        if (sbx.checked)
            policy.directives.sandbox = features;

        await RulesManager.addSessionRule(hostName, policy);
        await updateButtonStates(tab);
    });
}

async function populateOriginList(preferredDomain, tab) {
    tab ??= await sidepanel.getActiveTab();
    let frames = (await chrome.webNavigation.getAllFrames({tabId: tab.id}).catch(() => []) ?? [])
                     .filter(f => f.documentLifecycle === "active");
    let workers = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_WORKERS
    }).catch(() => []) ?? [];
    let domains = new Map();
    let topDomain;

    for (let f of frames) {
        let u = new URL(f.url);
        if (u.origin == "null")
            continue;
        let domain = await psl.getScopedDomain(u.hostname);
        if (!domains.has(domain))
            domains.set(domain, u.protocol);
        if (f.frameId === 0)
            topDomain = domain;
    }

    // Keep the preferred domain if it's still on the page, otherwise fall
    // back to the top frame's scoped key.
    let target = topDomain;
    if (domains.has(preferredDomain))
        target = preferredDomain;

    originList.replaceChildren();

    for (let [domain, protocol] of domains) {
        let btn = document.createElement("button");
        let span = document.createElement("span");
        let sw = unregistersw.cloneNode(true);
        btn.title = domain;
        btn.dataset.value = domain;
        btn.dataset.protocol = protocol;
        span.textContent = domain;
        sw.disabled = !workers.includes(domain);
        btn.append(span, sw);
        originList.appendChild(btn);
    }

    originList.value = target;
}

async function populateServerPolicy(tab) {
    tab ??= await sidepanel.getActiveTab();
    let headers;
    let serverFragment = document.createDocumentFragment();
    let columns = utils.getTableColProps(directivesTable, "id");
    let passthru = new Policy();

    headers = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_HEADERS,
           data: {
                id: tab?.id,
            domain: originList.value
        }
    }).catch(() => []);

    currentServerPolicies = headers.map(h => new Policy().fromHeader(h));

    passthru.directives = Object.create(null);

    for (let policy of currentServerPolicies) {
        for (let [directive, srcs] of Object.entries(policy.directives)) {
            let dir = Policy.collapseDirective(directive);

            if (columns.includes(dir)) {
                // Per the CSP spec, an empty source list is equivalent to 'none'.
                if (srcs.length === 0)
                    srcs = ["'none'"];
                for (let src of srcs) {
                    if (!sidepanel.isValidSource(src)) {
                        // Strip path suffixes from server sources (e.g. "example.com/path/"
                        // or "https://example.com/path"); the server's own CSP still enforces the path.
                        src = src.includes("://")
                            ? URL.parse(src)?.origin
                            : src.split("/", 1).at(0);
                    }
                    if (!sidepanel.isValidSource(src)) {
                        console.debug("report", `ignoring invalid or unsupported server source ${src}`);
                        continue;
                    }
                    setSourceCheckboxState(src, dir, true, undefined, serverFragment);
                }
            } else {
                passthru.directives[directive] ??= srcs;
            }
        }
    }

    // Hide any directives we will never allow.
    delete passthru.directives["report-to"];
    delete passthru.directives["report-uri"];

    // Don't clobber the table if the user is editing it when a new policy arrives.
    if (!serverTable.dataset.dirty) {
        serverTable.tBodies[0].replaceChildren(serverFragment);
        utils.sortTable(serverTable, compareSourceRows);
    }

    headerList.textContent = passthru.toHeader().trim();
}

async function refreshViolations(domain, tab) {
    tab ??= await sidepanel.getActiveTab();

    if (!domain || !tab) {
        // This can happen with multiple windows or devtools.
        console.debug("report", "refresh requested with unknown domain or tab", domain, tab);
        return null;
    }

    const violations = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_POLICY,
           data: {
                id: tab.id,
            domain: domain
        }
    }).catch(() => null);

    return violations;
}

// Allowlist http(s) only; everything else (chrome:, about:, devtools:, etc.)
// can't be reached by declarativeNetRequest so the controls would lie.
function updateOriginScopeState() {
    let proto = originList.protocol;

    document.body.classList.remove("inert");

    if (proto !== "http:" && proto !== "https:") {
        console.debug("report", `unhandled protocol ${proto}, disabling form`);
        document.body.classList.add("inert");
    }
}

// Commit and Abandon only make sense when there's a session rule for the
// host -- otherwise there's nothing to promote or discard. Uncommit is the
// inverse: a dynamic rule with no session draft in the way.
async function updateButtonStates(tab) {
    tab ??= await sidepanel.getActiveTab();
    let host = originList.value;
    let rules = RulesManager.getRules().filter(r => r.host === host);
    let hasSession = rules.some(r => r.isSession);
    let hasDynamic = rules.some(r => !r.isSession);
    let workers = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_WORKERS
    }).catch(() => []) ?? [];
    document.getElementById('commit').disabled = !hasSession;
    document.getElementById('abandon').disabled = !hasSession;
    document.getElementById('uncommit').disabled = !hasDynamic || hasSession;
    document.getElementById('reset').disabled = !hasSession && !hasDynamic;
    document.getElementById('resume').disabled = !RulesManager.isTabExempt(tab?.id);
    for (let btn of originList.querySelectorAll("button[data-value]")) {
        btn.querySelector("button.unregistersw").disabled = !workers.includes(btn.dataset.value);
    }
}

async function refreshTable(domain, tab) {
    let fragment = buildDefaultDirectivesFragment();

    tab ??= await sidepanel.getActiveTab();

    resetSandboxDirectives();
    delete serverTable.dataset.dirty;

    await getCurrentRules(domain, fragment);
    await populateServerPolicy(tab);
    setCurrentViolations(await refreshViolations(domain, tab), fragment);

    // Sort the fragment children before appending
    fragment.replaceChildren(...Array.from(fragment.children).sort(compareSourceRows));

    // Atomic swap
    directivesTable.tBodies[0].replaceChildren(fragment);

    await updateButtonStates(tab);
}

function populateTrustGroups() {
    let select = document.getElementById('trustgroup');
    let prev = select.value;
    let names = Object.keys(groups ?? {}).filter(name => name !== 'Ignore');

    select.replaceChildren(...names.map(name => {
        let opt = document.createElement('option');
        opt.textContent = name;
        opt.value = name;
        return opt;
    }));

    if (names.includes(prev))
        select.value = prev;
}

function updateReport() {
    return utils.callWithLock("report", async () => {
        let tab = await sidepanel.getActiveTab();
        await populateOriginList(userOrigin, tab);
        await refreshTable(originList.value, tab);
        populateTrustGroups();
        updateOriginScopeState();

        // If the user has opened the report, clear any icon badge.
        if (tab) chrome.action.setBadgeText({ text: '', tabId: tab.id }).catch(() => {});
    });
}

chrome.webNavigation.onCommitted.addListener(async (details) => {
    let tab = await sidepanel.getActiveTab();

    // Ignore notifications about other tabs.
    if (details.tabId !== tab?.id)
        return;

    updateReport();
});

chrome.tabs.onActivated.addListener((activeInfo) => {
    // Ignore notifications about other windows.
    if (activeInfo.windowId !== sidepanel.current.id)
        return;

    // Reset saved origin on navigation.
    userOrigin = undefined;
    updateReport();
});

async function handleNotifyUpdate(msg) {
    let tab = await sidepanel.getActiveTab();

    // Ignore updates for tabs we aren't viewing (tabId -1 is a Service Worker event).
    if (msg.data?.id !== -1 && msg.data?.id !== tab?.id)
        return;

    setCurrentViolations(await refreshViolations(originList.value, tab));
    await populateServerPolicy(tab);
    await updateButtonStates(tab);
    utils.sortTable(directivesTable, compareSourceRows);
}

chrome.runtime.onMessage.addListener((msg) => {
    switch (msg.command) {
        case MessageTypes.NOTIFY_UPDATE:
            utils.callWithLock("report", () => handleNotifyUpdate(msg));
            break;
        case MessageTypes.NOTIFY_RULES:
            // Another window mutated dNR rules; our mirror is stale.
            utils.callWithLock("report", async () => {
                await RulesManager.init();
                await refreshTable(originList.value);
            });
            break;
    }
});

Options.addUpdateListener(updateReport);
updateReport();
