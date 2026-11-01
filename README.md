
# matrix³

This is matrix³, an experimental content policy manager, inspired by
[umatrix](https://github.com/gorhill/uMatrix), but built on `declarativeNetRequest`.

It looks like this -- it adds a sidepanel that lets you enable or disable web
features for each site.

<img width="303" src="https://github.com/user-attachments/assets/aaa3d687-cf5d-432a-b38b-f4b02454843a" />

This extension basically just provides an interface to `Content-Security-Policy`, so
familiarity with the CSP3 specification is a bonus. It is currently just a prototype.


## Installation

Install the latest stable version via the [Chrome Web Store](https://chromewebstore.google.com/detail/matrix%C2%B3/hpdmcogknijiaifojoidaffonhefmkgo).

For the latest development version, follow these steps:

1. Clone or download this repository.
2. Open `chrome://extensions`.
3. Enable **Developer mode**, and click **Load Unpacked**.

## Usage

Open the sidepanel via the matrix³ toolbar icon. If this is your first time
using the extension, choose a default policy in the **Options** page.

If a site doesn't work, click the toolbar icon and open the **Report** page.
If you're using `sandbox`, try disabling it and see what resources the site
requests.

Any subresource the page requested that was denied is highlighted in orange.
You can enable options until the site works, then click **Reload** to reload
the tab.

When you're happy with the settings, click **Commit** to make them persistent.

### Suggested Policies

If the server suggests its own policy, you can either **Accept** or **Merge**
it with your own rules.

This is entirely optional, you can also ignore what the server suggests.

## Default Policies

The default policy is **Permissive**, which means nothing is blocked by default
until you configure specific rules.

If you find you want a more restrictive baseline, change the level in
**Options**. The available policies are described here.

### Permissive

Nothing is blocked by default. If you want to reduce permissions for a specific
site, you need to adjust it in the **Report** tab.

### First Party

First-party scripts and resources are generally allowed, along with third-party
images, styles, and fonts. Third-party scripts are blocked unless you
give them permission in the **Report** tab.

### Sandbox + Scripts

The `sandbox` attribute is applied to every document, but some scripts and
forms are allowed. Popups, downloads, and navigations are all blocked, and the
document runs in a strict isolated origin.

Many simple sites will work, but most complex sites will require exceptions in
the **Report** tab.

Cookies will *mostly* not work unless you enable "Allow Same Origin".

### Sandbox

The `sandbox` attribute is applied, with no exceptions.

Simple static sites will work, but no dynamic features will function. Forms
will not work without an exception.

### Strict

Effectively everything is disabled -- `default-src` is set to `'none'`.

Only first-party styles and images are permitted, all other resources are
blocked unless explicitly enabled.

## Rules

This extension provides an interface to *session* and *dynamic* rules, these
are `declarativeNetRequest` concepts.

A *dynamic* rule is **persistent** and is maintained when you restart Chrome.

A *session* rule is **ephemeral** and discarded when you restart Chrome. This
is the default, you must click **Commit** to make a rule *dynamic*.

The **Rules** panel shows all dynamic and session rules; you can delete
individual rules from there.

## Groups

A *group* is a named bundle of sources and directives you frequently want to
apply together -- for example, the CDNs you allow on most sites, or a set of
social media embed hosts.

Define groups and select the directives for each source in the **Groups**
page. Then in the **Report** page, pick a group from the dropdown and click
**Apply** to add all of its sources and checked directives for the current
host at once.

The **Ignore** group allows you to hide violations for specific sources and
directives (or all directives via `default-src`) from the **Report** page.

