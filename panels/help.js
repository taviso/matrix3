import * as sidepanel from '/include/sidepanel.js'
import * as utils from '/include/utils.js'

const template = document.getElementById('example-template');

for (let placeholder of document.querySelectorAll('table.sources')) {
    let table = template.content.cloneNode(true).firstElementChild;
    let cols = utils.getTableColProps(table, 'id');

    for (let tr of placeholder.querySelectorAll('tr[data-source]')) {
        let source = tr.dataset.source;
        let dirs = (tr.dataset.dirs ?? '').split(/\s+/);
        let row = table.tBodies[0].insertRow();
        let th = document.createElement('th');

        th.append(utils.formatSource(source));
        th.title = source;
        row.appendChild(th);

        for (let dir of cols.slice(1)) {
            let cell = row.insertCell();
            let box = document.createElement('input');
            box.type = 'checkbox';
            box.checked = dirs.includes(dir);
            box.indeterminate = dirs.includes(`!${dir}`);
            if (dirs.includes(`?${dir}`))
                box.classList.add('violation');
            cell.appendChild(box);
        }
    }

    placeholder.replaceWith(table);
}
