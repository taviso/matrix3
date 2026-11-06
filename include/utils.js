import Options from '/include/options.js'

export function clearTable(table) {
    table.tBodies[0]?.replaceChildren();
}

// Prompt the user when configured to prompt. Returns true when the action
// should go ahead.
export async function confirmAction(message) {
    let options = await Options.get();
    if (!options.confirmactions)
        return true;
    return confirm(message);
}

// Default comparator: alphabetical by the first cell's text content.
function compareRowLabels(a, b) {
    return a.cells[0].textContent.localeCompare(b.cells[0].textContent);
}

// Sort tbody rows by the given comparator (default: alphabetical by first
// cell's text content). Header rows in <thead> are untouched.
export function sortTable(table, compare = compareRowLabels) {
    table.tBodies[0].append(...Array.from(table.tBodies[0].rows).sort(compare));
}

// Return a property from each header cell, e.g. ('id') for column IDs or
// ('textContent') for column labels.
export function getTableColProps(table, prop) {
    return Array.from(table.tHead.rows[0].cells, c => c[prop]);
}

// Return a property from each body row's first cell -- typically the row
// label, e.g. ('textContent') for row titles.
export function getTableRowProps(table, prop) {
    return Array.from(table.tBodies[0].rows, r => r.cells[0][prop]);
}

// Find the body row whose first-cell text matches `label`, or undefined.
export function findTableRow(table, label) {
    return Array.from(table.tBodies[0].rows).find(r => r.cells[0].textContent === label);
}

// Set the checked state on every input in `list` (NodeList or any iterable).
export function setCheckboxes(list, state) {
    Array.from(list).forEach(box => box.checked = state);
}

// Enforce single-checked semantics across a checkbox group.
export function checkboxMutex(group, target) {
    let boxes = Array.from(group);

    if (!target.checked || !boxes.includes(target))
        return;

    boxes.filter(box => box !== target).forEach(box => box.checked = false);
}

// Wrap a leading "http(s)://" in a span so CSS can hide it visually while
// keeping the full source string in .textContent.
export function formatSource(source) {
    let frag = document.createDocumentFragment();
    let match = source.match(/^https?:\/\//);
    if (match) {
        let span = document.createElement("span");
        span.className = "scheme";
        span.textContent = match[0];
        frag.append(span, source.slice(match[0].length));
    } else {
        frag.append(source);
    }
    return frag;
}

// Serialize async work under a named Web Lock when available.
export function callWithLock(name, fn) {
    if (navigator.locks)
        return navigator.locks.request(name, fn);
    console.debug("utils", `web locks API not available, skipping lock ${name}`);
    return fn();
}
