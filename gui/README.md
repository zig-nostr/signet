# signer-app

**Signer Approvals** — a native desktop app that approves or denies Nostr
signing requests from your [signer daemon](../daemon).

> **Status: early / work in progress.** This is the interactive front end for
> the headless signer daemon. It connects to the daemon's loopback approval
> API, shows each pending request, and sends back your approve/deny decision,
> and spawns and supervises the daemon itself. `scripts/package-macos.sh`
> bundles both into a single `.app`; a signed, notarized distributable is next.

## Architecture

The signer is split into two processes on purpose:

- The **daemon** ([`daemon/`](../daemon))
  holds the secret key, connects to your relays, and does all Nostr work. In
  GUI mode it holds each request for approval and serves a **loopback-only**
  HTTP API.
- **This app** is a separate process that polls that API, shows each pending
  request, and sends back your approve/deny decision.

The key never enters this process — it only ever sees request metadata and
returns a yes/no. Built with the
[Native SDK](https://github.com/vercel-labs/native): declarative markup plus
Zig, rendered natively (no WebView, no Electron).

## Build

Requires [Zig](https://ziglang.org) 0.16.0 and the Native SDK CLI
(`npm install -g @native-sdk/cli`).

```sh
native dev      # build and run with hot reload
native test     # run the headless logic tests
native build    # produce a binary in zig-out/bin/
native check    # validate src/app.native + app.zon
```

## Connect to a signer

Run the daemon in **GUI mode** (see the signer's
[interactive approval](../daemon)
section) so it serves the loopback approval API, then point this app at it
with two environment variables:

- `SIGNER_APPROVAL_HTTP` — the daemon's approval address (default
  `127.0.0.1:8787`).
- `SIGNER_APPROVAL_TOKEN_FILE` — the bearer-token file the daemon wrote
  (default `$HOME/.zig-nostr-signer.token`).

```sh
SIGNER_APPROVAL_HTTP=127.0.0.1:8787 \
SIGNER_APPROVAL_TOKEN_FILE="$HOME/.zig-nostr-signer.token" \
  native dev
```

The app polls the queue (a long-poll chain, so it updates within a second of
a change), renders each pending request, and sends your decision back over
`POST /decision`. The bearer token authenticates every call; the secret key
stays in the daemon.

### Managed mode (the app supervises the daemon)

A packaged app is self-contained: the `.app` ships the `signer` daemon beside
the GUI in `Contents/MacOS`, and at launch the GUI discovers that sibling and
spawns it — one launch brings up both, no configuration. In development you get
the same one-launch behavior without packaging by pointing `SIGNER_BIN` at a
built daemon (it takes precedence over any bundled one):

```sh
SIGNER_BIN="$(which signer)" \
SIGNER_SECRET_KEY=<64-char hex, dev only — prefer SIGNER_KEY_FILE + SIGNER_PASSPHRASE> \
SIGNER_RELAYS="wss://relay.example.com" \
SIGNER_APPROVAL_HTTP=127.0.0.1:8787 \
SIGNER_APPROVAL_TOKEN_FILE="$HOME/.zig-nostr-signer.token" \
  native dev
```

Either way the daemon child inherits this process's environment (so it gets its
key and relay config), the app waits for it to write its token and then
connects, and if the daemon exits the app shows **Signer stopped** with a
**Restart** button. When the app quits, the daemon child is stopped with it, so
none is left orphaned holding the approval port. The key still only ever lives
in the daemon child.

## Packaging

`scripts/package-macos.sh` produces a single, self-contained
`Signer Approvals.app` with both executables side by side in `Contents/MacOS`
(`signer-app` and `signer`), so one download brings up both:

```sh
# builds the GUI, packages the .app, injects the daemon, and ad-hoc signs it
scripts/package-macos.sh --signer path/to/signer
```

The daemon comes from the [`daemon/`](../daemon) package in this repo; build it
(`cd ../daemon && zig build -Doptimize=ReleaseFast`) and the script finds
`../daemon/zig-out/bin/signer` on its own, or pass `--signer <path>`.

Ad-hoc signing (the default) is enough to run the bundle locally. A
distributable, Gatekeeper-friendly build additionally needs a Developer ID and
notarization, which require your own Apple credentials:

```sh
scripts/package-macos.sh --signing identity \
  --identity "Developer ID Application: Your Name (TEAMID)"
```

## Roadmap

- [x] App scaffold (native window, shell view, logic tests)
- [x] Approval queue over the daemon's loopback API (poll, approve, deny)
- [x] Supervise the daemon as a child process (one launch, key stays isolated)
- [x] Bundle the daemon into the app — one `.app`, discovered and supervised
- [ ] Signed, notarized distributable (Developer ID)
- [ ] First-run onboarding (generate/import a key) so a fresh download is turnkey

## License

MIT © Sepehr Safari
