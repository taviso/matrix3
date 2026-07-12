import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import * as psl from '/include/psl.js'
import Options from '/include/options.js'
import Policy from '/include/policy.js'
import { MessageTypes } from '/include/commands.js'

let RulesManager = sidepanel.RulesManager;
let options = await Options.get();

// Load any helpful hints and tooltips we have.
let helpData = { sources: [], directives: {}, sandbox: {} };

try {
    const [srcs, dirs, sbx] = await Promise.all([
        fetch(chrome.runtime.getURL('help/sources.json')).then(r => r.json()),
        fetch(chrome.runtime.getURL('help/directives.json')).then(r => r.json()),
        fetch(chrome.runtime.getURL('help/sandbox.json')).then(r => r.json())
    ]);
    helpData.sources = srcs.sources;
    helpData.directives = dirs.directives;
    helpData.sandbox = sbx.sandbox;

    // Attach tooltips to the static sandbox checkboxes.
    document.querySelectorAll("td input.sandbox").forEach(box => {
        box.title = helpData.sandbox[box.id] ?? "";
    });
} catch (e) {
    console.warn("report", "failed to load help data", e);
}

const directivesTable = document.querySelector("table#sources")
const sandboxTable = document.querySelector("table#sandbox")

const originList = document.querySelector("div#frames")

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

// Recognises the prefix of a CSP nonce-source or hash-source value.
const kNonceOrHashPrefix = /^'(?:nonce-|sha(?:256|384|512)-)/;

// Matches the base64 value suffix defined by the CSP3 grammar.
const kNonceOrHashFull = new RegExp(kNonceOrHashPrefix.source + /[A-Za-z0-9+/_-]+={0,2}'$/.source);

// Find all origins currently loaded in the tab that fall under the given scope.
async function getOriginsInScope(scope) {
    let tab = await sidepanel.getActiveTab();
    let frames = await chrome.webNavigation.getAllFrames({tabId: tab.id}) ?? [];
    let origins = new Set([`https://${scope}`]);

    for (let f of frames) {
        let u = new URL(f.url);
        if (await psl.getScopedDomain(u.hostname) === scope) {
            origins.add(u.origin);
        }
    }
    return Array.from(origins);
}

// Handle the main report buttons.
document.body.addEventListener('click', async (e) => {
    const host = originList.value;

    if (e.target.tagName !== 'BUTTON') return;

    switch (e.target.id) {
        case 'commit':
            await RulesManager.commitSessionRulesForHost(host);
            break;
        case 'reset':
            if (!await utils.confirmAction(`Remove all session and dynamic rules for ${host}?`)) return;
            await RulesManager.resetHostRules(host);
            if (options?.unregistersw) {
                chrome.browsingData.removeServiceWorkers(
                    { origins: await getOriginsInScope(host) }
                ).catch(e => console.warn("report", `failed to remove ${host} service workers`, e));
            }
            break;
        case 'abandon':
            if (!await utils.confirmAction(`Discard session changes for ${host}?`)) return;
            await RulesManager.abandonSessionRulesForHost(host);
            break;
        case 'uncommit':
            await RulesManager.uncommitDynamicRulesForHost(host);
            break;
        case 'reload':
            await chrome.tabs.reload(undefined, { bypassCache: e.shiftKey });
            return;
        case 'unblock':
            unblockReportedViolations();
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

document.getElementById('merge').addEventListener("click", () => applyServerPolicy());

// Transform a server-supplied source for import. Returns null to skip.
function importableSource(src) {
    if (!src)
        return null;
    if (kNonceOrHashPrefix.test(src))
        return null;
    if (src === "'report-sample'")
        return null;
    if (src === "'strict-dynamic'")
        return "'unsafe-inline'";
    return src;
}

function applyServerSources() {
    let columns = utils.getTableColProps(directivesTable, "id");

    for (let policy of currentServerPolicies) {
        for (let [directive, sources] of Object.entries(policy.directives)) {
            let dir = collapseDirective(directive);

            if (columns.includes(dir)) {
                sources.forEach(src => setSourceCheckboxState(importableSource(src), dir, true));
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

function applyServerSandbox() {
    let sbx = document.querySelector("input#sandbox-enabled");

    for (let policy of currentServerPolicies) {
        let features = policy.directives.sandbox;
        if (!features)
            continue;
        sbx.checked = true;
        for (let id of features) {
            let box = document.getElementById(id);
            if (box?.classList.contains("allow"))
                box.checked = true;
        }
    }
}

function unblockReportedViolations() {
    directivesTable.querySelectorAll("input.violation").forEach(b => b.checked = true);
    setCurrentRules(originList.value);
}
// Apply (or remove) the selected group's origins to default-src, script-src,
// style-src, and img-src. default-src covers other directives via inheritance;
// the rest are commonly set explicitly in strict policies so they need their
// own entries.
async function applyTrustGroup(checked) {
    let name = document.getElementById('trustgroup').value;
    let dirs = ["default-src", "script-src", "style-src", "img-src"];
    let origins;

    if (!name)
        return;

    origins = options.groups?.[name] ?? [];

    for (let origin of origins) {
        for (let dir of dirs) {
            let box = findCheckbox(origin, dir, checked);
            if (!box)
                continue;
            box.checked = checked;
            enforceNoneLeader(box);
        }
    }

    if (!checked)
        await fallbackToFirstParty();

    utils.sortTable(directivesTable, compareSourceRows);
    setCurrentRules(originList.value);
}

document.getElementById('trust').addEventListener("click", () => applyTrustGroup(true));
document.getElementById('untrust').addEventListener("click", () => applyTrustGroup(false));

originList.addEventListener("click", (e) => {
    let btn = e.target.closest("button");
    if (!btn) return;
    originList.value = btn.dataset.value;
    userOrigin = originList.value;
    refreshTable(originList.value);
    populateServerPolicy();
    updateOriginScopeState();
});

// 'none' must be alone in a CSP source list: checking 'none' clears the
// column, checking anything else clears 'none'.
function enforceNoneLeader(target) {
    let cell = target.closest("td");
    let noneRow = utils.findTableRow(directivesTable, "'none'");
    let col;
    let noneBox;
    let group;

    if (!target.checked)
        return;
    if (!cell || !noneRow)
        return;

    col = cell.cellIndex;
    noneBox = noneRow.cells[col].firstChild;
    group = Array.from(directivesTable.tBodies[0].rows, r => r.cells[col].firstChild);

    if (target === noneBox)
        utils.checkboxMutex(group, noneBox);
    else
        noneBox.checked = false;
}

directivesTable.addEventListener("change", (event) => {
    enforceNoneLeader(event.target);
    setCurrentRules(originList.value);
});
sandboxTable.addEventListener("change", async (event) => {
    if (event.target.id === "sandbox-enabled")
        await fallbackToFirstParty();
    setCurrentRules(originList.value);
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
    addSourceCheckboxRow("'strict-dynamic'", fragment);
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
    let ignored = options.groups?.Ignore ?? [];
    let row;
    let title;

    if (existing)
        return existing;
    if (ignored.includes(source))
        return null;

    row = document.createElement("tr");
    title = document.createElement("th");

    title.textContent = source;
    title.title = source;
    row.appendChild(title);

    for (let i = 1; i < cols.length; i++) {
        let cell = row.insertCell(-1);
        let box = document.createElement("input");
        box.type = "checkbox";
        box.checked = false;
        box.className = "rule";

        // Add any hint data we have for this combination.
        let sourceHelp = helpData.sources.find(h => new RegExp(h.regex).test(source));
        let directiveHelp = helpData.directives[cols[i]];

        if (directiveHelp)
            box.title += `${cols[i]}: ${directiveHelp}`;
        if (directiveHelp && sourceHelp)
            box.title += `\n\n`;
        if (sourceHelp && directiveHelp)
            box.title += sourceHelp.description;

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

    if (!row && autoAdd) {
        console.debug("report", `source name ${source} is unknown, adding`);
        row = addSourceCheckboxRow(source, container);
    }
    if (!row || colNum == -1) {
        // This could be something we just passthru
        if (!Policy.isAllowedPassthruDirective(directive, options?.defaultscope)) {
            // Nope, might be report-to or similar (safe to ignore).
            console.debug("report", `checkbox for ${directive} ${source} does not exist`);
        }
        return null;
    }

    return row.cells[colNum].firstChild;
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
        let dir = collapseDirective(directive);
        if (columns.includes(dir))
            sources.forEach(src => setSourceCheckboxState(importableSource(src), dir, true, undefined, container));
    }
}

// Sort sources alphabetically, but with nonce-* / sha*-* values at the end
// since they're noisy and rarely toggled.
function compareSourceRows(a, b) {
    let isHash = l => kNonceOrHashPrefix.test(l);
    let al = a.cells[0].textContent;
    let bl = b.cells[0].textContent;
    return (isHash(al) - isHash(bl)) || al.localeCompare(bl);
}

function collapseDirective(directive)
{
    switch (directive) {
        case "script-src-elem":
        case "script-src-attr":
            return "script-src";
        case "style-src-elem":
        case "style-src-attr":
            return "style-src";
    }
    return directive;
}

async function getCurrentRules(hostName, container)
{
    let rule = RulesManager.getHostRule(hostName);
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
            let sbx = document.querySelector("input#sandbox-enabled");
            let features = Array.from(document.querySelectorAll("td input.sandbox"));

            sbx.checked = true;
            for (let id of sources) {
                let box = features.find(f => f.id == id);
                box.checked = true;
            }
            continue;
        }

        if (directive == "report-uri" || directive == "base-uri")
            continue;

        let dir = collapseDirective(directive);
        for (let src of sources)
            setSourceCheckboxState(src, dir, true, className, container);
    }
}

function setCurrentViolations(data, container)
{
    for (let directive in data) {
        let dir = collapseDirective(directive);
        for (let src of data[directive])
            setSourceCheckboxClass(src, dir, "violation", container);
    }
}

async function setCurrentRules(hostName)
{
    let srcs = utils.getTableRowProps(directivesTable, "textContent");
    let dirs = utils.getTableColProps(directivesTable, "id");
    let policy = await RulesManager.getDefaultPolicy();

    // Drop the row-title column id.
    dirs.shift();

    // Passthrough security-relevant directives the server set that we don't
    // manage in the UI (frame-ancestors, trusted-types, etc.).
    let tab = await sidepanel.getActiveTab();
    let headers = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_HEADERS,
           data: {
                id: tab.id,
            domain: hostName
        }
    });
    let scope = options?.defaultscope;

    for (let header of headers) {
        let serverPolicy = new Policy().fromHeader(header);
        for (let d in serverPolicy.directives) {
            // We can't allow all directives through for domain scope, or
            // they'll apply to every host on that domain. This is a
            // tradeoff, rules are far easier for users to manage by domain,
            // but you have to accept the rules that allow the weakest hosts to
            // work. It can be configured by users though, via the scope option.
            if (!Policy.isAllowedPassthruDirective(d, scope)) {
                console.debug("report", `dropped directive ${d} for ${hostName}, not allowed in scope`);
                continue;
            }
            if (policy.directives[d]) {
                console.log("report", `duplicate directive ${d} dropped for ${hostName}`);
                continue;
            }
            policy.directives[d] = serverPolicy.directives[d];
        }
    }

    // Reset before write.
    dirs.forEach(dir => delete policy.directives[dir]);

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

    // Reset before write -- see NOTES.md "Inherited directives in setCurrentRules".
    delete policy.directives.sandbox;
    if (sbx.checked)
        policy.directives.sandbox = features;

    await RulesManager.addSessionRule(hostName, policy);
    updateButtonStates();
}

async function populateOriginList(preferredDomain) {
    let tab = await sidepanel.getActiveTab();
    let frames = await chrome.webNavigation.getAllFrames({tabId: tab.id}) ?? [];

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
        btn.textContent = domain;
        btn.dataset.value = domain;
        btn.dataset.protocol = protocol;
        originList.appendChild(btn);
    }

    originList.value = target;
}

async function populateServerPolicy() {
    let tab = await sidepanel.getActiveTab();
    let headers;
    let sources = new Set();

    headers = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_HEADERS,
           data: {
                id: tab.id,
            domain: originList.value
        }
    });

    headerList.value = headers.join("\n") || "none";

    currentServerPolicies = headers.map(h => new Policy().fromHeader(h));

    document.getElementById('accept').disabled = headers.length === 0;
    document.getElementById('merge').disabled = headers.length === 0;

    // Surface per-page nonce-* / hash-* sources from the server CSP so the
    // user can toggle them. Regex matches the CSP3 grammar exactly so we
    // reject anything with garbage characters.
    currentServerPolicies
        .flatMap(p => Object.values(p.directives).flat())
        .filter(src => kNonceOrHashFull.test(src))
        .forEach(src => sources.add(src));

    sources.forEach(src => addSourceCheckboxRow(src));

    utils.sortTable(directivesTable, compareSourceRows);
}

async function refreshViolations(domain) {
    let tab = await sidepanel.getActiveTab();

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
    });

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
function updateButtonStates() {
    let host = originList.value;
    let rules = RulesManager.getRules().filter(r => r.host === host);
    let hasSession = rules.some(r => r.isSession);
    let hasDynamic = rules.some(r => !r.isSession);
    let hasViolations = directivesTable.querySelector("input.violation") !== null;
    document.getElementById('commit').disabled = !hasSession;
    document.getElementById('abandon').disabled = !hasSession;
    document.getElementById('uncommit').disabled = !hasDynamic || hasSession;
    document.getElementById('unblock').disabled = !hasViolations;
    document.getElementById('reset').disabled = !hasSession && !hasDynamic;
}

async function refreshTable(domain) {
    let fragment = buildDefaultDirectivesFragment();

    resetSandboxDirectives();

    await getCurrentRules(domain, fragment);

    let violations = await refreshViolations(domain);

    if (violations) {
        setCurrentViolations(violations, fragment);
    }

    // Sort the fragment children before appending
    let rows = Array.from(fragment.children);
    rows.sort(compareSourceRows);

    fragment.replaceChildren(...rows);

    // Atomic swap
    directivesTable.tBodies[0].replaceChildren(fragment);

    updateButtonStates();
}

function populateTrustGroups() {
    let select = document.getElementById('trustgroup');
    let names = Object.keys(options.groups ?? {}).filter(name => name !== 'Ignore');

    select.replaceChildren(...names.map(name => {
        let opt = document.createElement('option');
        opt.textContent = name;
        opt.value = name;
        return opt;
    }));
}

async function updateReport() {
    let tab = await sidepanel.getActiveTab();
    await populateOriginList(userOrigin);
    await refreshTable(originList.value);
    populateServerPolicy();
    populateTrustGroups();
    updateOriginScopeState();

    // If the user has opened the report, clear any icon badge.
    if (tab) chrome.action.setBadgeText({ text: '', tabId: tab.id });
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

    // Ignore updates for tabs we aren't viewing.
    if (msg.data?.id !== tab?.id)
        return;

    let violations = await refreshViolations(originList.value);

    if (violations) {
        setCurrentViolations(violations);
        utils.sortTable(directivesTable, compareSourceRows);
        updateButtonStates();
    }

    populateServerPolicy();
    populateTrustGroups();
}

chrome.runtime.onMessage.addListener((msg) => {
    switch (msg.command) {
        case MessageTypes.NOTIFY_UPDATE:
            handleNotifyUpdate(msg);
            break;
        case MessageTypes.NOTIFY_RULES:
            // Another window mutated dNR rules; our mirror is stale.
            RulesManager.init().then(() => refreshTable(originList.value));
            break;
    }
});

Options.addUpdateListener(() => populateTrustGroups());
populateTrustGroups();
updateReport();
