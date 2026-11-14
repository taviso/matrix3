import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import Options from '/include/options.js'
import { MessageTypes } from '/include/commands.js'

const RulesManager = sidepanel.RulesManager;
const outputElement = document.getElementById("export");
const fileElement = document.getElementById("file");
const loadElement = document.getElementById("import");
const saveElement = document.getElementById("save");
const downloadElement = document.getElementById("download");
const pushElement = document.getElementById("push");
const pullElement = document.getElementById("pull");
const options = await Options.get();
const groups = await Options.getGroups();

async function refreshLastPush() {
    let time = await RulesManager.getCloudTime();
    let rules = await RulesManager.getCloudRules();
    let groups = await RulesManager.getCloudGroups();
    let element = document.getElementById("lastpush");

    if (!time) {
        element.textContent = "";
        return;
    }

    let when = new Date(time).toLocaleString();
    element.textContent = `Last cloud push: ${rules.length} rules, ${groups.length} groups, ${when}`;
}

async function buildExport() {
    let rules = RulesManager.getRules();
    return {
        session: rules.filter(r => r.isSession).map(r => r.toRule()),
        dynamic: rules.filter(r => !r.isSession).map(r => r.toRule()),
        options,
        groups,
        enabledRulesets: await chrome.declarativeNetRequest.getEnabledRulesets(),
    };
}

async function refreshExport() {
    outputElement.value = JSON.stringify(await buildExport());
}

downloadElement.addEventListener("click", () => {
    const blob = new Blob([outputElement.value], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "matrix3.json";
    link.click();
    URL.revokeObjectURL(url);
});

pushElement.addEventListener("click", async () => {
    if (!await utils.confirmAction("Push settings into cloud storage?"))
        return;
    try {
        let count = await utils.callWithLock("cloud", () => RulesManager.pushToCloud());
        console.log(`Successfully pushed ${count} dynamic rules to cloud.`);
    } catch (e) {
        alert("Push failed: " + e.message);
    } finally {
        await refreshLastPush();
    }
});

pullElement.addEventListener("click", async () => {
    if (!await utils.confirmAction("Pull settings from cloud storage?"))
        return;
    try {
        let count = await utils.callWithLock("cloud", () => RulesManager.pullFromCloud());
        console.log(`Successfully pulled ${count} dynamic rules from cloud.`);
    } catch (e) {
        alert("Pull failed: " + e.message);
    } finally {
        await refreshExport();
    }
});

async function saveExport() {
    let blob;
    try {
        blob = JSON.parse(outputElement.value);
    } catch (e) {
        alert("Invalid JSON: " + e.message);
        return;
    }

    if (!Options.isValid(blob?.options)) {
        alert("Invalid backup format.");
        return;
    }

    if (!await utils.confirmAction("Replace all current rules with imported ones?"))
        return;

    try {
        if (blob.session || blob.dynamic)
            await RulesManager.replaceAllRules(blob.session ?? null, blob.dynamic ?? null);

        if ((blob.groups && typeof blob.groups === "object") || blob.options?.groups) {
            for (let key of Object.keys(groups))
                delete groups[key];
            Object.assign(groups, { Ignore: {} }, blob.groups);
            await Options.saveGroups();
        }

        if (Options.migrate(blob.options))
            await Options.saveGroups();
        Object.assign(options, blob.options);
        await Options.save();

        // base is always-enabled and skipped by setEnabledRulesets anyway, but
        // filter it out explicitly so a stray "base" in the blob is benign.
        if (blob.enabledRulesets)
            await RulesManager.setEnabledRulesets(
                blob.enabledRulesets.filter(id => id !== "base")
            );
    } catch (e) {
        alert("Import failed: " + e.message);
    } finally {
        // applyOptions re-applies the defaultpolicy ruleset and the advanced class.
        await sidepanel.applyOptions();
        await refreshExport();
    }
}

loadElement.addEventListener("click", () => {
    fileElement.click();
});

fileElement.addEventListener("change", async () => {
    const [file] = fileElement.files;
    if (!file)
        return;
    outputElement.value = await file.text();
    fileElement.value = "";
    await saveExport();
});

saveElement.addEventListener("click", saveExport);

chrome.runtime.onMessage.addListener((msg) => {
    if (msg.command === MessageTypes.NOTIFY_RULES)
        RulesManager.init().then(refreshExport);
});

Options.addUpdateListener(refreshExport);

await refreshExport();
await refreshLastPush();
