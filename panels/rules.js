import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import { MessageTypes } from '/include/commands.js'

let RulesManager = sidepanel.RulesManager;

const dynamicTbl = document.getElementById('dynamic');
const sessionTbl = document.getElementById('session');
const staticTbl = document.getElementById('static');

async function updateRuleTables() {
    let rules = RulesManager.getRules();
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
        row.insertCell(-1).innerText = rule.host;
        let cell = row.insertCell(-1);
        cell.innerText = pol.toHeader();
        cell.title = cell.innerText;
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
    document.getElementById('reset').disabled = rules.length === 0;
    document.getElementById('commit').disabled = !rules.some(r => r.isSession);
}

function applyFilter() {
    const filterText = document.getElementById('filter').value.toLowerCase();
    for (let row of document.querySelectorAll('#dynamic tr, #session tr')) {
        if (row.innerText.toLowerCase().includes(filterText)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    }
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
document.getElementById('reset').addEventListener("click", async () => {
    if (!await utils.confirmAction("Remove all session and dynamic rules?"))
        return;
    await RulesManager.resetAllRules();
    updateRuleTables();
});

chrome.runtime.onMessage.addListener((msg) => {
    switch (msg.command) {
        case MessageTypes.NOTIFY_RULES:
            // Another window mutated dNR rules; our mirror is stale.
            RulesManager.init().then(() => updateRuleTables());
            break;
    }
});

updateRuleTables();
