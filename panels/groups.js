import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import Options from '/include/options.js'

const groupsContainer = document.getElementById('groups');
const newnameInput = document.getElementById('newname');
const groupTemplate = document.getElementById('group-template');
const options = await Options.get();

options.groups ??= {};
options.groups.Ignore ??= {};

async function saveGroups() {
    await Options.save();
}

function addSourceRow(table, groupName, source, directives) {
    let cols = utils.getTableColProps(table, "id");
    let colNodes = table.querySelectorAll("colgroup col");
    let row = document.createElement("tr");
    let title = document.createElement("th");
    let delBtn = document.createElement("button");
    let span = document.createElement("span");

    row.dataset.origin = source;

    delBtn.className = "delorigin";
    delBtn.title = "Remove";
    delBtn.textContent = "×";
    delBtn.addEventListener("click", () => removeOrigin(groupName, source));

    span.className = "origin-name";
    span.textContent = source;

    title.title = source;
    title.append(delBtn, span);
    row.appendChild(title);

    for (let i = 1; i < cols.length; i++) {
        let cell = row.insertCell(-1);
        let box = document.createElement("input");
        box.type = "checkbox";
        box.checked = directives.includes(cols[i]);
        box.className = "rule";
        box.title = sidepanel.getRuleTooltip(source, cols[i]);

        if (colNodes[i].classList.contains("advanced"))
            cell.classList.add("advanced");
        cell.appendChild(box);
    }

    table.tBodies[0].appendChild(row);
}

function updateGroupsDisplay() {
    groupsContainer.replaceChildren();

    for (let [name, origins] of Object.entries(options.groups)) {
        let g = groupTemplate.content.cloneNode(true).firstElementChild;
        let table = g.querySelector('table.sources');
        let input = g.querySelector('.neworigin');
        let cols = utils.getTableColProps(table, "id");

        g.dataset.name = name;
        g.querySelector('.group-name').textContent = name;
        g.querySelector('.delgroup').addEventListener('click', () => deleteGroup(name));
        g.querySelector('.addorigin').addEventListener('click', () => addOrigin(name, input.value));
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter')
                addOrigin(name, input.value);
        });

        for (let [origin, dirs] of Object.entries(origins)) {
            addSourceRow(table, name, origin, dirs);
        }

        utils.sortTable(table);

        table.addEventListener('change', async (event) => {
            let row = event.target.closest('tr');
            if (!row)
                return;
            let origin = row.dataset.origin;
            options.groups[name][origin] = cols.slice(1).filter((_, i) => row.cells[i + 1].firstChild.checked);
            await saveGroups();
        });

        groupsContainer.appendChild(g);
    }
}

async function addGroup() {
    let name = newnameInput.value.trim();

    if (!name)
        return;
    if (name in options.groups)
        return;

    options.groups[name] = {};
    newnameInput.value = '';
    await saveGroups();
    updateGroupsDisplay();
}

async function deleteGroup(name) {
    if (!await utils.confirmAction(`Delete group ${name}?`))
        return;
    delete options.groups[name];
    await saveGroups();
    updateGroupsDisplay();
}

async function addOrigin(group, origin) {
    origin = origin.trim();

    if (!origin)
        return;
    if (!sidepanel.isValidSource(origin))
        return;
    if (origin in options.groups[group])
        return;

    options.groups[group][origin] = [];
    await saveGroups();
    updateGroupsDisplay();
}

async function removeOrigin(group, origin) {
    delete options.groups[group][origin];
    await saveGroups();
    updateGroupsDisplay();
}

document.getElementById('addgroup').addEventListener('click', () => addGroup());
newnameInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter')
        addGroup();
});

updateGroupsDisplay();
