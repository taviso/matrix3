import sourcesData from '/help/sources.json' with { type: 'json' };
import directivesData from '/help/directives.json' with { type: 'json' };
import sandboxData from '/help/sandbox.json' with { type: 'json' };

export default class Help {
    static sources = sourcesData.sources.map(h => ({ ...h, regex: new RegExp(h.regex) }));
    static directives = directivesData.directives;
    static sandbox = sandboxData.sandbox;

    static getSourceHelp(source) {
        if (typeof source !== "string")
            return undefined;
        return Help.sources.find(h => h.regex.test(source));
    }

    static getRuleTooltip(source, directive) {
        let sourceHelp = Help.getSourceHelp(source);
        let directiveHelp = Help.directives[directive]?.description;
        let title = "";

        if (directiveHelp)
            title += `${directive}: ${directiveHelp}`;
        if (directiveHelp && sourceHelp)
            title += `\n\n${sourceHelp.description}`;

        return title;
    }

    static isValidSource(source) {
        return !!Help.getSourceHelp(source);
    }
}
