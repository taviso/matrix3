
// The default options if none are set.
const kDefaultOptions = {
    version: 2,
    defaultpolicy: 0,
    advanced: false,
    badges: true,
    confirmactions: false,
    unregistersw: true,
    defaultscope: "domain",
};

// Each entry at key `v` migrates an options object in place from `v` to `v + 1`.
// Avoid backwards-breaking type changes across versions where possible: an older
// browser may still receive a newer blob via chrome.storage.sync and will try
// its best to read it in-memory while refusing to write back until updated.
const kMigrations = {
    1: (opts) => {
        const dirs = ["default-src", "script-src", "style-src", "img-src"];
        for (let [name, group] of Object.entries(opts.groups ?? {})) {
            if (Array.isArray(group)) {
                opts.groups[name] = Object.fromEntries(group.map(o => [o, [...dirs]]));
            }
        }
    },
};

// A cache of chrome.storage.sync's `options` key, we want to check options in
// a lot of hot paths, and a storage.sync.get call everytime is suboptimal.
export default class Options {
    static #cache = null;
    static #promise;
    static #listeners = [];

    static migrate(opts) {
        let v = opts.version ?? 1;
        if (v > kDefaultOptions.version) {
            console.warn("options", `options version ${v} is newer than supported ${kDefaultOptions.version}`);
            return false;
        }
        if (v === kDefaultOptions.version)
            return false;

        for (; v < kDefaultOptions.version; v++) {
            console.debug("options", `migrating options v${v} -> v${v + 1}`);
            kMigrations[v]?.(opts);
            opts.version = v + 1;
        }
        return true;
    }

    static #load() {
        Options.#promise ??= chrome.storage.sync.get("options").then(({ options }) => {
            if (options)
                options.version ??= 1;
            // Default configuration for fresh installations or partial objects.
            Options.#cache = Object.assign({}, kDefaultOptions, options);
            if (Options.migrate(Options.#cache))
                Options.save();
            chrome.storage.onChanged.addListener((changes) => {
                if (!changes.options)
                    return;
                let newValue = changes.options.newValue;
                if (newValue)
                    newValue.version ??= 1;
                // Mutate in place so consumers can hold a stable reference.
                for (let key of Object.keys(Options.#cache))
                    delete Options.#cache[key];
                Object.assign(Options.#cache, kDefaultOptions, newValue);
                Options.migrate(Options.#cache);
                for (let callback of Options.#listeners)
                    callback(Options.#cache);
            });
        });
        return Options.#promise;
    }

    static async get() {
        if (Options.#cache === null)
            await Options.#load();
        return Options.#cache;
    }

    static async save() {
        if (Options.#cache === null)
            await Options.#load();
        if (Options.#cache.version > kDefaultOptions.version) {
            console.warn("options", `refusing to save over newer options v${Options.#cache.version}`);
            alert("Options were synced from a newer version of matrix³. Please update the extension to save changes.");
            return false;
        }
        await chrome.storage.sync.set({ options: Options.#cache });
        return true;
    }

    static addUpdateListener(callback) {
        Options.#listeners.push(callback);
    }
}
