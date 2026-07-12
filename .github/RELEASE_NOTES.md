**Signet** — a native NIP-46 remote signer for Nostr. macOS, **ad-hoc signed (not notarized)**.

### Install

Download the `Signet-*-macos.zip` asset below, unzip it, and move `Signet.app` to `/Applications`.

Because Signet isn't notarized, macOS quarantines the download and Gatekeeper blocks the first launch. Clear the quarantine flag once — this is the reliable step:

```sh
xattr -dr com.apple.quarantine /Applications/Signet.app
open /Applications/Signet.app
```

(Finder's right-click → **Open**, or **System Settings → Privacy & Security → Open Anyway**, works on some setups too — but on recent macOS an ad-hoc app is often flagged *"is damaged"*, where only the command above clears it.)

Either way you're only clearing the "downloaded from the internet" marker; the app stays ad-hoc signed. The trust anchor is a reproducible build — this artifact was built by CI from the tagged commit, and you can rebuild it yourself (see the [README](https://github.com/zig-nostr/signet#build)). **Your key never leaves the daemon.**
