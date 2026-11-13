import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import { MessageTypes } from '/include/commands.js'

let RulesManager = sidepanel.RulesManager;

const dynamicTbl = document.getElementById('dynamic');
const sessionTbl = document.getElementById('session');
const staticTbl = document.getElementById('static');

const kDirectiveIcons = [
    ["📌", "default-src"],
    ["📜", "script-src"],
    ["🦚", "style-src"],
    ["🖼️", "img-src"],
    ["🪟", "frame-src"],
    ["🔤", "font-src"],
    ["📽️", "media-src"],
    ["🔌", "connect-src"],
    ["🔧", "worker-src"],
    ["⚙️", "child-src", "manifest-src", "object-src"],
    ["🔒", "sandbox"],
];

function renderPolicyCell(cell, pol) {
    for (let [icon, ...dirs] of kDirectiveIcons) {
        let active = dirs.filter(d => d in pol.directives);
        let span = document.createElement("span");
        span.className = "directive";
        span.textContent = icon;
        span.title = active.map(d => `${d}: ${pol.directives[d].join(" ")}`).join("; ");
        span.classList.toggle("unused", !active.length);
        span.classList.toggle("disabled", active.length > 0 && active.every(d => pol.directives[d].includes("'none'")));
        cell.appendChild(span);
    }

    let raw = document.createElement("span");
    raw.hidden = true;
    raw.textContent = pol.toHeader();
    cell.appendChild(raw);
}

function updateRuleTables() {
    return utils.callWithLock("rules", async () => {
        let rules = RulesManager.getRules().sort((a, b) => a.host.localeCompare(b.host));
        let base  = RulesManager.getAllStaticRules();

        utils.clearTable(dynamicTbl);
        utils.clearTable(sessionTbl);

        for (let rule of rules) {
            let tbl = rule.isSession ? sessionTbl : dynamicTbl;
            let row = tbl.insertRow(-1);
            let chk = document.createElement("input");
            let pol = rule.policy;

            delete pol.directives["report-uri"];

            chk.type = "checkbox";
            chk.checked = false;
            chk.className = "rule";
            chk.dataset.id = rule.id;
            row.insertCell(-1).appendChild(chk);
            let hostCell = row.insertCell(-1);
            hostCell.innerText = rule.host;
            hostCell.title = rule.host;
            renderPolicyCell(row.insertCell(-1), pol);
        }

        utils.clearTable(staticTbl);

        for (let ruleset of base) {
            let row = staticTbl.insertRow(-1);
            let chk = document.createElement("input");
            chk.type = "checkbox";
            chk.checked = await ruleset.isEnabled();
            chk.disabled = true;
            chk.className = "rule";
            chk.title = "Adjust Rulesets in Options...";
            row.insertCell(-1).appendChild(chk);
            row.insertCell(-1).innerText = ruleset.id;
        }

        applyFilter();
        document.getElementById('remove').disabled = rules.length === 0;
        document.getElementById('commit').disabled = !rules.some(r => r.isSession);
        document.getElementById('selectdynamic').disabled = !rules.some(r => !r.isSession);
        document.getElementById('invertdynamic').disabled = !rules.some(r => !r.isSession);
        document.getElementById('selectsession').disabled = !rules.some(r => r.isSession);
        document.getElementById('invertsession').disabled = !rules.some(r => r.isSession);
    });
}

function getRuleRows(table) {
    return Array.from(table ? table.rows : document.querySelectorAll('#dynamic tr, #session tr'));
}

function selectAll(table) {
    const filterText = document.getElementById('filter').value.toLowerCase();
    getRuleRows(table)
        .filter(r => r.textContent.toLowerCase().includes(filterText))
        .forEach(r => r.cells[0].firstChild.checked = true);
}

function invertSelection(table) {
    const filterText = document.getElementById('filter').value.toLowerCase();
    getRuleRows(table)
        .filter(r => r.textContent.toLowerCase().includes(filterText))
        .forEach(r => r.cells[0].firstChild.checked = !r.cells[0].firstChild.checked);
}

function applyFilter() {
    const filterText = document.getElementById('filter').value.toLowerCase();
    getRuleRows().forEach(r => r.hidden = false);
    getRuleRows()
        .filter(r => !r.textContent.toLowerCase().includes(filterText))
        .forEach(r => r.hidden = true);
}

document.getElementById('filter').addEventListener('input', applyFilter);

document.getElementById('remove').addEventListener("click", async () => {
    let checked = Array.from(document.querySelectorAll('input.rule:checked:not(:disabled)'));

    // Confirm action if multiple rules are checked.
    if (checked.length > 5 && !await utils.confirmAction(`Remove ${checked.length} rules?`)) {
        return;
    }

    let rules = RulesManager.getRules();
    let ruleFromId = id => rules.find(r => r.id === id);

    for (let chk of checked) {
        let rule = ruleFromId(parseInt(chk.dataset.id));
        await RulesManager.delRule(rule);
    }

    updateRuleTables();
});

document.getElementById('commit').addEventListener("click", async () => {
    // Promote any checked sesion rules.
    for (let row of sessionTbl.rows) {
        if (!row.cells[0].firstChild.checked)
            continue;
        await RulesManager.commitSessionRulesForHost(row.cells[1].innerText);
    }
    updateRuleTables();
});
document.getElementById('selectdynamic').addEventListener("click", () => selectAll(dynamicTbl));
document.getElementById('invertdynamic').addEventListener("click", () => invertSelection(dynamicTbl));
document.getElementById('selectsession').addEventListener("click", () => selectAll(sessionTbl));
document.getElementById('invertsession').addEventListener("click", () => invertSelection(sessionTbl));

chrome.runtime.onMessage.addListener((msg) => {
    switch (msg.command) {
        case MessageTypes.NOTIFY_RULES:
            // Another window mutated dNR rules; our mirror is stale.
            RulesManager.init().then(updateRuleTables);
            break;
    }
});

updateRuleTables();
