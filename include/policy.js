// This class is just a simple representation of a csp policy.

// The default blank policy you get from new Policy()
const kDefaultPolicy = {
    "report-uri": [ "https://_matrix3.internal/csp-report" ],
};

export default class Policy {
    // Default directives -- override per instance as needed.
    directives = structuredClone(kDefaultPolicy);

    // Server-CSP directives we preserve. Per-document ones need host scope --
    // they can't merge across siblings in a domain-scoped bucket.
    static isAllowedPassthruDirective(directive, scope) {
        switch (directive) {
            case "upgrade-insecure-requests":
            case "block-all-mixed-content":
                return true;
            case "frame-ancestors":
            case "form-action":
            case "require-trusted-types-for":
            case "trusted-types":
            case "base-uri":
                return scope === "host";
        }
        return false;
    }

    static collapseDirective(directive) {
        switch (directive) {
            case "script-src-elem":
            case "script-src-attr":
                return "script-src";
            case "style-src-elem":
            case "style-src-attr":
                return "style-src";
        }
        return directive;
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

    // Convert from our internal representation into a HTTP header.
    toHeader() {
        let headerString = "";
        for (let directive in this.directives) {
            headerString += directive;
            headerString += " ";
            headerString += this.directives[directive].join(" ");
            headerString += "; ";
        }
        return headerString;
    }
}
