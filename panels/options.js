import * as sidepanel from '/include/sidepanel.js'
import Options from '/include/options.js'

const optionElements = document.querySelectorAll(".option");
const policyRange = document.getElementById("defaultpolicy");
const options = await Options.get();

function updatePolicyTitle(val = policyRange.value) {
    let opt = policyRange.list?.querySelector(`option[value="${val}"]`);
    policyRange.title = opt?.title || opt?.label || "";
}

function syncOptionChanges(event) {
    let val = event.target.value;

    if (event.target.type === "checkbox")
        val = event.target.checked;
    else if (event.target.type === "range")
        val = parseInt(val);

    options[event.target.id] = val;
    Options.save();
    sidepanel.applyOptions();
}

// Reflect cached options into form state. Called once at startup and again
// whenever another window mutates options.
function updateOptions() {
    for (let el of optionElements) {
        if (el.type === "checkbox")
            el.checked = options[el.id];
        else if (options[el.id] !== undefined)
            el.value = options[el.id];
    }
    updatePolicyTitle();
}

// Watch for changes, then sync them to the options object.
optionElements.forEach(el => el.addEventListener("change", syncOptionChanges));
policyRange.addEventListener("input", () => updatePolicyTitle());
policyRange.addEventListener("mousemove", (e) => {
    let max = Number(policyRange.max) || 4;
    let idx = Math.min(max, Math.max(0, Math.round((e.offsetX / policyRange.clientWidth) * max)));
    updatePolicyTitle(idx);
});
policyRange.addEventListener("mouseleave", () => updatePolicyTitle());

Options.addUpdateListener(updateOptions);
updateOptions();
