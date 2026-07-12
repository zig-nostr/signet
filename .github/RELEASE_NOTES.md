**Signet** — a native NIP-46 remote signer for Nostr. macOS, **ad-hoc signed (not notarized)**.

### Install

Download the `Signet-*-macos.zip` asset below, unzip it, and move `Signet.app` to `/Applications`.

Because Signet isn't notarized, macOS Gatekeeper blocks the first launch. To open it:

- **Finder (no Terminal):** Control-click (right-click) `Signet.app` → **Open**, then **Open** in the dialog. On recent macOS, if that's still blocked, open **System Settings → Privacy & Security**, scroll to *Security*, and click **Open Anyway** next to the Signet message.
- **If macOS says it "is damaged":** it isn't — that's the download-quarantine flag on an ad-hoc-signed app, for which Apple withholds the one-click Finder bypass. Clear it from Terminal instead:

  ```sh
  xattr -dr com.apple.quarantine /Applications/Signet.app
  open /Applications/Signet.app
  ```

Either way you're only clearing the "downloaded from the internet" marker; the app stays ad-hoc signed. The trust anchor is a reproducible build — this artifact was built by CI from the tagged commit, and you can rebuild it yourself (see the [README](https://github.com/zig-nostr/signet#build)). **Your key never leaves the daemon.**
