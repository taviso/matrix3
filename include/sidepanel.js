import Rules from '/include/rules.js'
import Options from '/include/options.js'

export let current = await chrome.windows.getCurrent();
let options = await Options.get();

const panel = document.getElementById("panel");

// chrome.tabs.getCurrent() is undefined in side-panel/popup contexts.
if (await chrome.tabs.getCurrent())
    document.body.classList.add("standalone");

export let RulesManager = new Rules();
export let helpData = { sources: [], directives: {}, sandbox: {} };

try {
    const [srcs, dirs, sbx] = await Promise.all([
        fetch(chrome.runtime.getURL('help/sources.json')).then(r => r.json()),
        fetch(chrome.runtime.getURL('help/directives.json')).then(r => r.json()),
        fetch(chrome.runtime.getURL('help/sandbox.json')).then(r => r.json()),
    ]);
    helpData.sources = srcs.sources.map(h => ({ ...h, regex: new RegExp(h.regex) }));
    helpData.directives = dirs.directives;
    helpData.sandbox = sbx.sandbox;
} catch (e) {
    console.warn("sidepanel", "failed to load help data", e);
}

export function getRuleTooltip(source, directive)
{
    let sourceHelp = helpData.sources.find(h => h.regex.test(source));
    let directiveHelp = helpData.directives[directive];
    let title = "";

    if (directiveHelp)
        title += `${directive}: ${directiveHelp}`;
    if (directiveHelp && sourceHelp)
        title += `\n\n${sourceHelp.description}`;

    return title;
}

export function isValidSource(source)
{
    return helpData.sources.some(h => h.regex.test(source));
}

const sidepanelPages = {
    "Report": "/panels/report.html",
     "Rules": "/panels/manage.html",
    "Groups": "/panels/groups.html",
   "Options": "/panels/options.html",
    "Export": "/panels/export.html",
      "Help": "/panels/help.html",
     "About": "/panels/about.html",
};

Options.addUpdateListener(applyOptions);

for (let page in sidepanelPages) {
    let opt = document.createElement("option");
    opt.innerText = page;
    opt.value = sidepanelPages[page];
    opt.selected = location.pathname == opt.value;
    panel.add(opt);
}

panel.addEventListener("change", event => {
    location.href = event.target.value;
});

export async function getActiveTab()
{
    let [ tab ] = await chrome.tabs.query({windowId: current.id, active: true});
    return tab;
}

// Apply persistent option changes (advanced-class toggle, default policy).
export async function applyOptions()
{
    await RulesManager.init();

    document.body.classList.toggle("show-advanced", !!options.advanced);

    if (options.defaultpolicy !== undefined)
        await RulesManager.applyDefaultPolicy(options.defaultpolicy);
}

await applyOptions();
