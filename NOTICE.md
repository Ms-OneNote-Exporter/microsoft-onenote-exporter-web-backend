# NOTICE

## License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for
the full text.

## Commercial use

The MIT License grants anyone the right to use, copy, modify, merge, publish,
distribute, sublicense and sell copies of this software, including for
commercial purposes. **No permission is required, and none is withheld.**

This NOTICE cannot add conditions to the MIT License, and does not attempt to.
If you are reading this hoping it sets rules, it does not: the terms in
[LICENSE](LICENSE) are the terms.

**A courtesy request, not a restriction:** if you use this commercially, or build
on it in a way you make money from, please **let the author know** — an issue or
a note is welcome. This is a request out of interest in the project, not a
condition of use. Nobody can enforce it, and no licence condition depends on it.

## Attribution

The copyright notice and the MIT permission notice must be retained in all
copies or substantial portions of the Software. Keeping the author's name in
the files is the one real obligation MIT does impose, and it is why the author
field is populated in `package.json`.

## Origin

Built on the same foundations as the rest of the family:
[microsoft-webauth](https://github.com/Ms-OneNote-Exporter/microsoft-webauth),
[microsoft-onenote-list-notebooks](https://github.com/Ms-OneNote-Exporter/microsoft-onenote-list-notebooks),
[microsoft-onenote-export-notebook](https://github.com/Ms-OneNote-Exporter/microsoft-onenote-export-notebook),
[microsoft-onenote-exporter](https://github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter).

Those packages are consumed from npm unmodified and are not forked. This
repository is the hosted service around them.

## What this project does that the packages do not

The sibling packages authenticate **locally** and hand you a `storageState`
file you own. This repository puts the same pipeline behind a web service, and
that difference is worth stating plainly rather than glossing:

**It asks you to type your Microsoft account password into a web form.** The
password is `POST`ed from your browser to the API origin over TLS and forwarded
to an isolated session container **without parsing, logging or persistence**.
Only the runner container processes it. It is never written to disk, and it is
gone when you erase your session. But the request exists, and no amount of
transport hygiene changes that.

Microsoft does not offer an export surface that avoids this: the Graph API caps
page retrieval on large SharePoint-backed notebooks and requires Entra
administrator rights, which a service authenticating arbitrary personal
accounts does not have. `PLANNING/PLAN-v3.md` §0.2 records the full reasoning
with upstream citations, including the residual objection — that a service which
replays credentials normalises handing passwords to websites, and phishing
thrives on that habit. That objection is a product-level decision and it belongs
to whoever operates the service.

**If you are not willing to hand a Microsoft password to a web service, use
[`microsoft-onenote-exporter`](https://github.com/Ms-OneNote-Exporter/microsoft-onenote-exporter)
instead.** It produces the same Obsidian-flavoured vault locally and no password
leaves your machine. It is a fully supported alternative, not a consolation
prize, and the frontend is required to say so (PLAN-v3 §10 T11).

Login is automated by `microsoft-webauth`, which accepts updated Terms of Use
and Microsoft consent pages by matching a fixed set of button labels. **Accepting
the Services Agreement is a real change to your account.** The consent text
shown before the password field states this.

This project is unofficial and is not affiliated with or endorsed by Microsoft.

## Handling of credentials

`auth.json` — a Playwright `storageState`, i.e. live session cookies — is
written under the session directory on the server, not on your machine.
Anyone who reads it can act as you until the session expires.

Two upstream debug facilities are **unreachable from this service** and must
stay that way: `--dodump` writes a DOM dump containing authenticated cookies and
tenant hostnames, and `--screenshot` cannot redact credential fields, because a
screenshot is a bitmap — while still showing an MFA code. In a hosted service
either one is a credential artefact, so "no debug override" is a security
control here and not a tidiness preference (PLAN-v3 §5.6, §9 invariant 13,
test `T-X5`).

Session state is erased on request and on TTL expiry. Erasure is `rm -rf` plus
best-effort shred, which is not a cryptographic erase; see PLAN-v2 §11.

## Third-party content

The Microsoft Q&A page preserved as
`docs/graphapi-sharepoint-notebook-limit-evidence.pdf` in
`microsoft-onenote-export-notebook` is **Microsoft's content, not this
project's**, and is quoted as evidence outside the MIT licence. Nothing from
that file is vendored into this repository.
