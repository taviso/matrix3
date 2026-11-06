
// The default options if none are set.
const kDefaultOptions = {
    version: 3,
    defaultpolicy: 0,
    advanced: false,
    badges: true,
    confirmactions: false,
    unregistersw: true,
    defaultscope: "domain",
    privatedomains: false,
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
    2: (opts, groups) => {
        if (opts.groups) {
            for (let [name, group] of Object.entries(opts.groups))
                groups[name] = Object.assign(groups[name] ?? {}, group);
            delete opts.groups;
        }
    },
};

// A cache of chrome.storage.sync's `options` key and chrome.storage.local's
// `groups` key; we check both in hot paths, so querying storage every time is
// suboptimal.
export default class Options {
    static #cache = null;
    static #groups = null;
    static #promise;
    static #listeners = [];

    static {
        chrome.storage.onChanged.addListener(Options.#onChanged);
    }

    static migrate(opts, groups = Options.#groups ??= { Ignore: {} }) {
        let v = opts.version ?? 1;
        if (v > kDefaultOptions.version) {
            console.warn("options", `options version ${v} is newer than supported ${kDefaultOptions.version}`);
            return false;
        }
        if (v === kDefaultOptions.version)
            return false;

        for (; v < kDefaultOptions.version; v++) {
            console.debug("options", `migrating options v${v} -> v${v + 1}`);
            kMigrations[v]?.(opts, groups);
            opts.version = v + 1;
        }
        return true;
    }

    static async #onChanged(changes, area) {
        if (area !== "sync" && area !== "local")
            return;
        await Options.#load();

        if (area === "sync" && changes.options) {
            let newValue = changes.options.newValue;
            if (newValue)
                newValue.version ??= 1;
            // Mutate in place so consumers can hold a stable reference.
            for (let key of Object.keys(Options.#cache))
                delete Options.#cache[key];
            Object.assign(Options.#cache, kDefaultOptions, newValue);
            if (Options.migrate(Options.#cache))
                await Options.#saveInternal(true);
        } else if (area === "local" && changes.groups) {
            for (let key of Object.keys(Options.#groups))
                delete Options.#groups[key];
            Object.assign(Options.#groups, { Ignore: {} }, changes.groups.newValue);
        } else {
            return;
        }

        for (let callback of Options.#listeners)
            callback(Options.#cache);
    }

    static #load() {
        Options.#promise ??= (async () => {
            let [{ options }, { groups }] = await Promise.all([
                chrome.storage.sync.get("options"),
                chrome.storage.local.get("groups"),
            ]);
            if (options)
                options.version ??= 1;

            Options.#groups = Object.assign({ Ignore: {} }, groups);

            // Default configuration for fresh installations or partial objects.
            Options.#cache = Object.assign({}, kDefaultOptions, options);
            if (Options.migrate(Options.#cache))
                await Options.#saveInternal(true).catch(console.warn);
        })();
        return Options.#promise;
    }

    static async get() {
        await Options.#load();
        return Options.#cache;
    }

    static async getGroups() {
        await Options.#load();
        return Options.#groups;
    }

    static async save() {
        await Options.#load();
        return Options.#saveInternal();
    }

    static async #saveInternal(migrated = false) {
        if (Options.#cache.version > kDefaultOptions.version) {
            console.warn("options", `refusing to save over newer options v${Options.#cache.version}`);
            alert("Options were synced from a newer version of matrix³. Please update the extension to save changes.");
            return false;
        }
        let toSet = { options: Options.#cache };
        if (migrated) {
            await chrome.storage.local.set({ groups: Options.#groups });
            let keys = Object.keys(Options.#groups).map(name => `group:${name}`);
            let existing = await chrome.storage.sync.get(keys);
            for (let [name, group] of Object.entries(Options.#groups))
                toSet[`group:${name}`] = Object.assign({}, existing[`group:${name}`], group);
        }
        await chrome.storage.sync.set(toSet);
        if (migrated) {
            let { synced } = await chrome.storage.local.get("synced");
            await chrome.storage.local.set({
                synced: { rules: synced?.rules ?? [], groups: Options.#groups },
            });
        }
        return true;
    }

    static async saveGroups() {
        await Options.#load();
        await chrome.storage.local.set({ groups: Options.#groups });
        return true;
    }

    static addUpdateListener(callback) {
        Options.#listeners.push(callback);
    }
}
