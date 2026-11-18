// This class is just a simple representation of a csp policy.
import Help from '/include/help.js'

// Directives managed by matrix³; any other directives (e.g. legacy passthrough
// directives like block-all-mixed-content, frame-ancestors, or trusted-types)
// are left to the server's own CSP header and stripped from appended rules.
const kManagedDirectives = new Set([
    ...Object.keys(Help.directives),
    "report-uri",
]);

// Recognises the prefix of a CSP nonce-source or hash-source value.
const kNonceOrHashPrefix = /^'(?:nonce-|sha(?:256|384|512)-)/i;
const kNoncePrefix = /^'nonce-/i;

export default class Policy {
    directives;

    constructor(headerString = "") {
        this.fromHeader(headerString);
    }

    static isNonceOrHash(src) {
        return typeof src === "string" && kNonceOrHashPrefix.test(src);
    }

    static isNonceOrStrictDynamic(src) {
        return typeof src === "string" && (kNoncePrefix.test(src) || src === "'strict-dynamic'");
    }

    // Transform a source token for matrix³'s own appended policy. Nonces,
    // hashes, and 'strict-dynamic' cannot be emitted in matrix³'s policy
    // (they would suppress 'unsafe-inline' or host sources) and map to
    // 'unsafe-inline' while the server's policy enforces the actual nonce/hash.
    static importableSource(src) {
        if (!src || typeof src !== "string")
            return null;
        if (Policy.isNonceOrHash(src) || src === "'strict-dynamic'")
            return "'unsafe-inline'";
        if (!Help.isValidSource(src))
            return null;
        return src;
    }

    static collapseDirective(directive) {
        switch (directive) {
            case "script-src-elem":
            case "script-src-attr":
                return "script-src";
            case "style-src-elem":
            case "style-src-attr":
                return "style-src";
            case "fenced-frame-src":
                return "frame-src";
        }
        return directive;
    }

    // Return the effective source list for a fetch directive after walking the
    // CSP3 fallback chain, or undefined if no governing directive is set.
    getEffectiveSources(directive) {
        const fallbacks = {
            "worker-src": ["worker-src", "child-src", "script-src", "default-src"],
            "frame-src":  ["frame-src", "child-src", "default-src"],
        };
        const chain = fallbacks[directive]
            ?? (directive.endsWith("-src") ? [directive, "default-src"] : [directive]);

        for (let dir of chain) {
            if (dir in this.directives)
                return this.directives[dir];
        }
        return undefined;
    }

    // True when a fetch directive resolves to 'none' (or an empty source list).
    isDirectiveDisabled(directive) {
        let sources = this.getEffectiveSources(directive);
        return sources !== undefined && (sources.length === 0 || sources.includes("'none'"));
    }

    // Initialize from a HTTP header.
    fromHeader(headerString = "") {
        let headerTokens = headerString.trim().split(';').filter(f => f.length);

        // Reset directives to a null-prototype object to prevent pollution.
        this.directives = Object.create(null);

        for (let token of headerTokens) {
            const directive = token.trim().split(/\s+/);
            const directiveName = directive.shift().toLowerCase();

            if (!directiveName)
                continue;

            // Per W3C, only the first occurrence of a directive is honored.
            if (directiveName in this.directives) {
                console.warn("policy", "skipping duplicate directive", directiveName);
                continue;
            }

            this.directives[directiveName] = directive;
        }
        return this;
    }

    // Normalize directive sources for an appended matrix³ policy, stripping
    // unmanaged passthrough directives and translating any legacy
    // nonce/hash/'strict-dynamic' tokens to 'unsafe-inline'.
    sanitizeForAppend() {
        for (let [directive, sources] of Object.entries(this.directives)) {
            if (!kManagedDirectives.has(directive)) {
                delete this.directives[directive];
                continue;
            }
            if (directive === "report-uri" || directive === "sandbox")
                continue;
            let mapped = sources.map(s => Policy.importableSource(s)).filter(Boolean);
            if (directive === "script-src" && sources.some(s => Policy.isNonceOrStrictDynamic(s)))
                mapped.push("'self'");
            this.directives[directive] = Array.from(new Set(mapped));
        }
        return this;
    }

    // Convert from our internal representation into a HTTP header.
    toHeader() {
        let headerString = "";
        for (let directive in this.directives) {
            headerString += [directive, ...this.directives[directive]].join(" ");
            headerString += "; ";
        }
        return headerString;
    }
}
