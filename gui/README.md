# Signer Approvals — the Signet GUI

The native desktop approver for **Signet** — approve or deny Nostr signing
requests. This is the `gui/` component of the
[Signet](https://github.com/zig-nostr/signet) product; the secret key stays in
the signer daemon ([`../daemon`](../daemon)).

> **Status: early / work in progress.** This is the interactive front end for
> the headless signer daemon. The scaffold opens the window and renders the
> shell; wiring it to the daemon's loopback approval API — poll the queue,
> approve or deny each request — lands next.

## Architecture

The signer is split into two processes on purpose:

- The **daemon** ([`../daemon`](../daemon)) holds the secret key, connects to
  your relays, and does all Nostr work. In GUI mode it holds each request for
  approval and serves a **loopback-only** HTTP API.
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

## Roadmap

- [x] App scaffold (native window, shell view, logic tests)
- [ ] Approval queue over the daemon's loopback API (poll, approve, deny)
- [ ] Supervise the daemon as a child process (one download, key stays isolated)
- [ ] Packaged, signed, downloadable build

## License

MIT © Sepehr Safari
