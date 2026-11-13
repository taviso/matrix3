import * as sidepanel from '/include/sidepanel.js'
import { MessageTypes } from '/include/commands.js'

const RulesManager = sidepanel.RulesManager;
const manifest = chrome.runtime.getManifest();
const version = document.getElementById("version");
const topDirectives = document.getElementById("topdirectives").tBodies[0];
const topSources = document.getElementById("topsources").tBodies[0];

version.textContent = `v${manifest.version}`;

fetch(chrome.runtime.getURL("version.json"))
    .then(r => r.json())
    .then(v => {
        if (v.commit)
            version.textContent = `v${manifest.version} (${v.commit})`;
    })
    .catch(() => {});

function fillTable(tbody, entries, formatLabel) {
    tbody.replaceChildren();
    for (let [name, count] of entries) {
        let row = tbody.insertRow();
        let cell = row.insertCell();
        cell.textContent = formatLabel ? formatLabel(name) : name;
        cell.title = sidepanel.helpData.directives[name]?.description ?? name;
        row.insertCell().textContent = count;
    }
}

function refreshStats() {
    let rules = RulesManager.getRules();
    let session = rules.filter(r => r.isSession).length;
    let dynamic = rules.length - session;
    let directives = new Map();
    let sources = new Map();

    document.getElementById("stats").textContent = `${session} session rules, ${dynamic} dynamic rules.`;

    for (let rule of rules) {
        for (let [dir, srcs] of Object.entries(rule.policy.directives)) {
            if (dir === "report-uri" || dir === "report-to")
                continue;
            directives.set(dir, (directives.get(dir) ?? 0) + 1);
            if (dir === "sandbox")
                continue;
            for (let src of srcs) {
                if (src !== "'none'")
                    sources.set(src, (sources.get(src) ?? 0) + 1);
            }
        }
    }

    fillTable(
        topDirectives,
        [...directives.entries()].sort((a, b) => b[1] - a[1]),
        d => `${sidepanel.helpData.directives[d]?.icon ?? ""} ${d}`
    );
    fillTable(
        topSources,
        [...sources.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20)
    );
}

chrome.runtime.onMessage.addListener((msg) => {
    if (msg.command === MessageTypes.NOTIFY_RULES)
        RulesManager.init().then(refreshStats);
});

refreshStats();
