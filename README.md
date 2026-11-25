
# matrix³

This is matrix<sup>3</sup>, a minimalist content policy manager inspired by
[umatrix](https://github.com/gorhill/uMatrix), but built on `declarativeNetRequest`.

It looks like this -- it adds a sidepanel that lets you enable or disable web
features for each site.

[<img width="200" src="https://github.com/user-attachments/assets/86bc9ece-e87f-4942-84e1-ff83578c77bd" />](https://github.com/user-attachments/assets/86bc9ece-e87f-4942-84e1-ff83578c77bd)

There is built-in help, and an introduction available in the [wiki](https://github.com/taviso/matrix3/wiki/Getting-Started).

## Installation

Install the latest stable version via the [Chrome Web Store](https://chromewebstore.google.com/detail/matrix%C2%B3/hpdmcogknijiaifojoidaffonhefmkgo).

[![Chrome Web Store Version](https://img.shields.io/chrome-web-store/v/hpdmcogknijiaifojoidaffonhefmkgo?style=for-the-badge&logo=chromewebstore&logoColor=yellow&logoSize=auto&color=lightgreen)](https://chromewebstore.google.com/detail/matrix%C2%B3/hpdmcogknijiaifojoidaffonhefmkgo)

For the latest development version, follow these steps:

1. Clone or download this repository.
2. Open `chrome://extensions`.
3. Enable **Developer mode**, and click **Load Unpacked**.

## Usage

Open the sidepanel via the matrix<sup>3</sup> toolbar icon. If this is your first time
using the extension, you can choose a default policy in the **Options** panel.

If a site doesn't work, click the toolbar icon and open the **Report** panel to
troubleshoot site permissions.

Any subresource the page requested that was denied is highlighted in orange.
You can enable options until the site works, then click **Reload** to reload
the tab.

When you're happy with the settings, click **Commit** to make your changes persistent.
