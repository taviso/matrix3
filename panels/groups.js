import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import Options from '/include/options.js'

const groupsContainer = document.getElementById('groups');
const newnameInput = document.getElementById('newname');
const groupTemplate = document.getElementById('group-template');
const options = await Options.get();

options.groups ??= {};
options.groups.Ignore ??= {};

function updateBoxTooltip(box, groupName, source, directive) {
    let base = sidepanel.getRuleTooltip(source, directive);
    if (groupName === "Ignore") {
        let state = box.checked ? "be IGNORED"
                  : (box.indeterminate || directive === "default-src") ? "be REPORTED"
                  : "follow default-src";
        box.title = `${base}\n\nViolations for this directive will ${state}.`;
    } else {
        let state = box.checked ? "CHECKED"
                  : box.indeterminate ? "UNCHECKED"
                  : "UNCHANGED";
        box.title = `${base}\n\nThis directive will be ${state}.`;
    }
}

function addSourceRow(table, groupName, source, directives) {
    let cols = utils.getTableColProps(table, "id");
    let colNodes = table.querySelectorAll("colgroup col");
    let row = document.createElement("tr");
    let title = document.createElement("th");
    let delBtn = document.createElement("button");

    row.dataset.origin = source;

    delBtn.className = "delorigin";
    delBtn.title = "Remove";
    delBtn.textContent = "×";
    delBtn.addEventListener("click", () => removeOrigin(groupName, source));

    title.title = source;
    title.append(delBtn, utils.formatSource(source));
    row.appendChild(title);

    for (let i = 1; i < cols.length; i++) {
        let cell = row.insertCell(-1);
        let box = document.createElement("input");
        box.type = "checkbox";
        box.checked = directives.includes(cols[i]);
        box.indeterminate = directives.includes(`!${cols[i]}`);
        box.className = "rule";
        updateBoxTooltip(box, groupName, source, cols[i]);

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
        g.querySelector('.addorigin').addEventListener('click', () => addOrigin(name, input));
        input.addEventListener('input', () => input.setCustomValidity(''));
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter')
                addOrigin(name, input);
        });

        for (let [origin, dirs] of Object.entries(origins)) {
            addSourceRow(table, name, origin, dirs);
        }

        utils.sortTable(table);

        table.addEventListener('change', async (event) => {
            let box = event.target;
            let row = box.closest('tr');
            if (!row)
                return;
            let origin = row.dataset.origin;
            let dir = cols[box.closest('td').cellIndex];
            let prev = options.groups[name][origin];

            // Cycle: unchecked -> checked -> indeterminate -> unchecked.
            if (prev.includes(dir)) {
                box.checked = false;
                box.indeterminate = true;
            } else if (prev.includes(`!${dir}`)) {
                box.checked = false;
            }

            updateBoxTooltip(box, name, origin, dir);

            options.groups[name][origin] = cols.slice(1).flatMap((col, i) => {
                let input = row.cells[i + 1].firstChild;
                if (input.checked)
                    return [col];
                if (input.indeterminate)
                    return [`!${col}`];
                return [];
            });
            await Options.save();
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
    await Options.save();
    updateGroupsDisplay();
}

async function deleteGroup(name) {
    if (!await utils.confirmAction(`Delete group ${name}?`))
        return;
    delete options.groups[name];
    await Options.save();
    updateGroupsDisplay();
}

async function addOrigin(group, input) {
    let origin = input.value.trim();

    if (!origin)
        return;
    if (!sidepanel.isValidSource(origin)) {
        input.setCustomValidity(input.title);
        input.reportValidity();
        return;
    }
    if (origin in options.groups[group])
        return;

    options.groups[group][origin] = [];
    await Options.save();
    updateGroupsDisplay();
}

async function removeOrigin(group, origin) {
    delete options.groups[group][origin];
    await Options.save();
    updateGroupsDisplay();
}

document.getElementById('addgroup').addEventListener('click', addGroup);
newnameInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter')
        addGroup();
});

updateGroupsDisplay();
