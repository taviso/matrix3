import Rules from '/include/rules.js'
import Options from '/include/options.js'

export let current = await chrome.windows.getCurrent();
let options = await Options.get();

const panel = document.getElementById("panel");

// chrome.tabs.getCurrent() is undefined in side-panel/popup contexts.
if (await chrome.tabs.getCurrent())
    document.body.classList.add("standalone");

export let RulesManager = new Rules();

const sidepanelPages = {
    "Report": "/panels/report.html",
     "Rules": "/panels/manage.html",
    "Groups": "/panels/groups.html",
   "Options": "/panels/options.html",
    "Export": "/panels/export.html",
      "Help": "/panels/help.html",
     "About": "/panels/about.html",
};

Options.addUpdateListener(() => applyOptions());

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
