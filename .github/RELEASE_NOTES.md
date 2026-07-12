**Signet** — a native NIP-46 remote signer for Nostr. macOS (Apple Silicon), **ad-hoc signed (not notarized)**.

### Install

```sh
curl -fsSL https://raw.githubusercontent.com/zig-nostr/signet/main/scripts/install-macos.sh | bash
```

The installer downloads the latest release, verifies its SHA-256, installs `Signet.app` to `/Applications`, and opens it — ready to use.

Signet is ad-hoc signed, not notarized, on purpose: it holds your keys, so the trust anchor is a build you can reproduce, not an Apple signature. Read the [installer](https://github.com/zig-nostr/signet/blob/main/scripts/install-macos.sh) or [build from source](https://github.com/zig-nostr/signet#build). **Your key never leaves the daemon.**
