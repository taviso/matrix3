// Public Suffix List lookup. The exported API is intentionally minimal so
// the implementation can be swapped without touching callers.
//
import { parse } from '/vendor/tldts.js';
import Options from '/include/options.js'

const kHostnameChars = new Set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_[:]"
);

function parseHost(host, options)
{
    if (typeof host !== "string" || !new Set(host).isSubsetOf(kHostnameChars))
        return null;
    let url = URL.parse(`http://${host}:80`);
    if (!url)
        return null;
    let parsed = parse(url.hostname, {
        allowPrivateDomains: !!options?.privatedomains,
    });
    if (parsed.isIp)
        parsed.hostname = url.hostname;
    return parsed.hostname ? parsed : null;
}

// Returns the normalized, validated hostname for `host` (stripping any
// trailing FQDN dot), or null if `host` is not a valid DNS/IPv4/IPv6 hostname.
export function getHostname(host)
{
    return parseHost(host)?.hostname ?? null;
}

// Returns the registrable domain for `host`, e.g. "mail.google.com" ->
// "google.com". Falls back to the validated hostname for IPs and single-label
// hosts (e.g. "127.0.0.1", "localhost"), or null for invalid hostnames.
export async function getRegistrableDomain(host)
{
    let options = await Options.get();
    let parsed = parseHost(host, options);
    return parsed ? (parsed.domain ?? parsed.hostname) : null;
}

// Resolves `host` to the scope the user picked in Options. "domain" is the
// PSL registrable; "host" returns the validated literal hostname (or null).
export async function getScopedDomain(host)
{
    let options = await Options.get();

    switch (options?.defaultscope) {
        case "host":
            return getHostname(host);
        case "domain":
        default:
            return getRegistrableDomain(host);
    }
}
