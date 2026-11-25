import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import Help from '/include/help.js'
import { MessageTypes } from '/include/commands.js'

let RulesManager = sidepanel.RulesManager;

const dynamicTbl = document.getElementById('dynamic');
const sessionTbl = document.getElementById('session');
const staticTbl = document.getElementById('static');

const kDirectiveGroups = Map.groupBy(
    Object.keys(Help.directives),
    d => Help.directives[d].advanced ? "⚙️" : Help.directives[d].icon
);

function renderPolicyCell(cell, pol) {
    for (let [icon, dirs] of kDirectiveGroups) {
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
            row.rule = rule;
            Object.defineProperty(row, "checked", {
                get: () => chk.checked,
                set: (v) => { chk.checked = v; },
            });
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
        let hasDynamic = rules.some(r => !r.isSession);
        let hasSession = rules.some(r => r.isSession);
        document.querySelectorAll('#dynamiccontrols button').forEach(b => b.disabled = !hasDynamic);
        document.querySelectorAll('#sessioncontrols button').forEach(b => b.disabled = !hasSession);
    });
}

function getRuleRows(table) {
    return Array.from(table ? table.rows : document.querySelectorAll('#dynamic tr, #session tr'));
}

function selectAll(table) {
    getRuleRows(table).filter(r => !r.hidden).forEach(r => r.checked = true);
}

function invertSelection(table) {
    getRuleRows(table).filter(r => !r.hidden).forEach(r => r.checked = !r.checked);
}

function applyFilter() {
    const filterText = document.getElementById('filter').value.toLowerCase();
    getRuleRows().forEach(r => {
        r.hidden = !r.textContent.toLowerCase().includes(filterText);
    });
}

document.getElementById('filter').addEventListener('input', applyFilter);

async function removeSelected(table) {
    let checked = getRuleRows(table).filter(r => r.checked);

    // Confirm action if multiple rules are checked.
    if (checked.length > 5 && !await utils.confirmAction(`Remove ${checked.length} rules?`)) {
        return;
    }

    for (let row of checked) {
        await RulesManager.delRule(row.rule);
    }

    updateRuleTables();
}

document.getElementById('uncommit').addEventListener("click", async () => {
    for (let row of getRuleRows(dynamicTbl).filter(r => r.checked)) {
        await RulesManager.uncommitDynamicRulesForHost(row.rule.host);
    }
    updateRuleTables();
});

document.getElementById('commit').addEventListener("click", async () => {
    for (let row of getRuleRows(sessionTbl).filter(r => r.checked)) {
        await RulesManager.commitSessionRulesForHost(row.rule.host);
    }
    updateRuleTables();
});

document.getElementById('selectdynamic').addEventListener("click", () => selectAll(dynamicTbl));
document.getElementById('invertdynamic').addEventListener("click", () => invertSelection(dynamicTbl));
document.getElementById('removedynamic').addEventListener("click", () => removeSelected(dynamicTbl));
document.getElementById('selectsession').addEventListener("click", () => selectAll(sessionTbl));
document.getElementById('invertsession').addEventListener("click", () => invertSelection(sessionTbl));
document.getElementById('removesession').addEventListener("click", () => removeSelected(sessionTbl));

chrome.runtime.onMessage.addListener((msg) => {
    switch (msg.command) {
        case MessageTypes.NOTIFY_RULES:
            // Another window mutated dNR rules; our mirror is stale.
            RulesManager.init().then(updateRuleTables);
            break;
    }
});

updateRuleTables();
