# gmail-tidy-mcp

[![npm](https://img.shields.io/npm/v/gmail-tidy-mcp)](https://www.npmjs.com/package/gmail-tidy-mcp)
[![test](https://github.com/imkath/gmail-tidy-mcp/actions/workflows/test.yml/badge.svg)](https://github.com/imkath/gmail-tidy-mcp/actions/workflows/test.yml)
[![license](https://img.shields.io/github/license/imkath/gmail-tidy-mcp)](LICENSE)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-io.github.imkath%2Fgmail--tidy--mcp-blue)](https://registry.modelcontextprotocol.io/v0/servers?search=gmail-tidy-mcp)

An MCP server that lets your AI assistant read and organize several Gmail accounts at once: search, read, label, archive, set up filters and write drafts.

It cannot send or delete email. Not "it asks first": there is no tool for it, and a test fails the build if a send or delete call ever shows up in the code.

## Why

Most Gmail MCP servers hand the model full control of your mailbox, including sending, and keep OAuth tokens in plain text on disk. That is a lot of trust to give a model that also reads emails written by strangers.

This one is built around a smaller promise: the assistant can help you get your inbox in order, but it can't send anything or delete anything.

## What it can do

| Area | Tools |
|---|---|
| Accounts | `list_accounts`, `check_accounts`, `connect_account`, `finish_connect_account` |
| Reading | `search_emails` (Gmail search syntax), `get_email` (lists attachments), `get_attachment` (text, `.gz` and `.zip` are read inline, e.g. DMARC reports; anything else, like a PDF, is saved to `~/Downloads/gmail-tidy-mcp`), `sender_stats` (who writes most, by address and domain) |
| Labels | `list_labels`, `create_label` (nest with `Parent/Child`), `update_label` (rename, recolor with the Gmail palette, show or hide in the sidebar) |
| Organizing | `organize_emails`: add or remove labels by ID or by search, up to 5,000 messages at a time. Archive = remove `INBOX`, mark as read = remove `UNREAD` |
| Filters | `list_filters`, `create_filter`, `delete_filter`. A filter that skips the inbox needs an explicit `skip_inbox: true` |
| Drafts | `create_draft`, optionally as a reply inside a thread. You send it yourself from Gmail |
| Settings | `set_signature`: changes only the signature, never how mail goes out |
| Audit | `recent_changes`: every change this server made, to review or undo a session |

Each account gets a short label, so you can say things like "archive every newsletter older than a month in *work*".

## What it will not do

- Send, reply, forward or delete email, or move it to Trash or Spam.
- Give the model a way to add those later: the tools are fixed in code and the model cannot call arbitrary Gmail endpoints.

Google has no scope that allows drafts but not sending, so the server asks for `gmail.modify` (which technically includes sending) plus `gmail.settings.basic` for filters. The guarantee comes from the code, and `test/safety.test.js` checks it on every run.

## Security

- **Tokens are encrypted** with AES-256-GCM in `~/.config/gmail-tidy-mcp/tokens.enc` (mode 600). The key lives in the macOS Keychain, the Linux Secret Service (`secret-tool`), or a DPAPI-protected file on Windows. You can also provide it yourself with `GMAIL_TIDY_KEY` (64 hex characters).
- **Sign-in uses PKCE and a random `state`**, with the redirect on `127.0.0.1` only.
- **The signed-in account is verified.** After sign-in, the server asks Gmail which address it got. If it is not the one you asked for, or Google granted different scopes, the token is revoked and nothing is saved.
- **Your own OAuth client.** No shared client and no third-party server. Your mail goes from Google to your machine and nowhere else.
- **Email content is fenced off as untrusted.** Everything read from Gmail goes inside a block whose markers carry a random value per call, so an email can't close the block early. Control characters in headers are removed, and HTML is reduced to visible text (scripts, styles, and text hidden with `display:none`, `visibility:hidden`, `font-size:0` or `opacity:0` are dropped).
- **Invisible text is removed.** Unicode tag characters (used to smuggle instructions that a model reads but you can't see), zero-width characters and text-direction controls are stripped from headers, bodies and attachments. Tag characters are reported, since they have no legitimate use in mail.
- **Security notes come from the server, not the sender.** `get_email` and `get_attachment` add a short list of findings above the untrusted block: phrasing typical of prompt injection, failed SPF, DKIM or DMARC, a Reply-To that sends answers to a free webmail address when the sender didn't pass DMARC, a display name that pretends to be another address, and links that show one site but lead to another (Gmail and Outlook redirect wrappers are unwrapped first; tracking links in mailing lists are not flagged). They are tuned to stay quiet on normal mail, so a note means something.
- **Lookalike senders are flagged.** A sender whose domain is one or two letters away from one of your connected accounts (or uses letters from other scripts that look Latin) gets a note; for Gmail and other webmail the mailbox name is compared instead. Mail between your own accounts is never flagged.
- **Every change is logged locally.** Labels, archiving, filters, drafts, signature changes and saved files are appended to `~/.config/gmail-tidy-mcp/audit.log` (mode 600), without message bodies, draft text or the signature itself. `recent_changes` shows them, so if something odd happened in a session you can see exactly what and undo it.
- **Dangerous attachments are not saved.** Executables and scripts, disguised names (`factura.pdf.exe`, right-to-left override tricks), files whose bytes don't match their extension, and archives that contain any of those are refused unless the call says `allow_risky: true`. Password-protected archives, macro-enabled Office files and PDFs with JavaScript or auto-run actions are flagged. Saved files never overwrite anything, can't be written outside the downloads folder, and on macOS get the quarantine flag so Gatekeeper checks them before they open.
- **Drafts can't smuggle headers.** Line breaks in To, Cc, Subject or the reply headers are rejected, so nobody can sneak in a hidden Bcc.
- **Arguments are validated** before anything reaches Gmail, and the tools that change things carry MCP annotations (`destructiveHint`) so clients can ask you before running them.
- Two runtime dependencies (`@modelcontextprotocol/sdk` and `googleapis`), pinned to exact versions, none with install scripts.

### What could still go wrong

No server can make prompt injection impossible, and the security notes are heuristics: they catch common tricks, not every one, and a clean result proves nothing. If a malicious email convinces the model, it could still:

- relabel or archive mail (you can undo this),
- create a filter that hides new mail from the inbox (only with `skip_inbox: true`, and your client can ask you first),
- delete one of your filters (filters can't be recovered),
- write a misleading draft. It is never sent unless you send it,
- rename or recolor a label, or change your signature (all reversible),
- save an attachment flagged as dangerous, if it also sets `allow_risky: true`; opening it is still up to you.

Two more things worth knowing:

- **The token itself can send mail.** The "never send" guarantee is in this code, not in the token. If someone steals the token and the key, they get what `gmail.modify` allows. Keep your machine and keyring locked.
- **On macOS, the Keychain item trusts `/usr/bin/security`**, which means any process running as you can read the key without a prompt. That still keeps the key off the disk, but it is not a barrier against malware running under your user.

## Setup

Requires Node.js 22 or newer.

### 1. Create your Google OAuth client (once)

1. In [Google Cloud Console](https://console.cloud.google.com/), create a project and enable the **Gmail API**.
2. In **Google Auth Platform**, set up the app as **External**, add your email as the support and contact address, and publish it (**Audience → Publish app**). Unverified apps in production keep their refresh tokens. In testing mode they expire after 7 days.
3. Under **Clients**, create a client of type **Desktop app** and download the JSON.
4. Save it as `~/.config/gmail-tidy-mcp/oauth-client.json` and make it private (`chmod 600` on macOS and Linux).

When you connect an account, Google warns that the app is unverified. That is expected: the app is yours. Continue through **Advanced**.

### 2. Register it with your MCP client

Claude Code:

```bash
claude mcp add -s user gmail-tidy -- npx -y gmail-tidy-mcp
```

Any other MCP client: run `npx -y gmail-tidy-mcp` over stdio.

Prefer to run it from source? Clone the repo, run `npm ci --ignore-scripts`, and point your client at `node /path/to/gmail-tidy-mcp/bin/gmail-tidy-mcp.js`.

On Linux, install `libsecret-tools` first so the key can go into your keyring.

### 3. Connect accounts

Ask your assistant to connect an account. It opens Google's sign-in page in your browser. Or do it from the terminal:

```bash
npx gmail-tidy-mcp add you@gmail.com personal
npx gmail-tidy-mcp list
npx gmail-tidy-mcp remove you@gmail.com
```

Removing an account deletes its token locally. To revoke access on Google's side too, go to [myaccount.google.com/permissions](https://myaccount.google.com/permissions).

Google Workspace accounts may need an admin to allow unverified apps.

## Development

```bash
npm test
```

The tests cover the safety guarantee (no send or delete calls, no Trash or Spam, filter actions limited to labels), token encryption and key handling, the sign-in callback (state, errors, timeouts), the post-login checks, draft headers and body decoding. CI runs them on Linux, macOS and Windows, including the real DPAPI path on Windows.

## Credits

This started from [gx-55/multi-gmail-mcp](https://github.com/gx-55/multi-gmail-mcp) (MIT) by Rogers Xie. Some of its building blocks remain: the label-or-address account lookup, the message search and header helpers, the reply threading and the token-error detection. The storage, sign-in flow, tool set and safety model were redesigned.

## License

MIT. See [LICENSE](LICENSE).
