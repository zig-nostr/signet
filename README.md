# signer

A headless [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md)
remote signer ("bunker") for Nostr, built on the
[zig-nostr/nostr](https://github.com/zig-nostr/nostr) library.

It keeps your `nsec` on a machine you control and signs on behalf of web and
native clients over a relay — the secret key never reaches the client.

> **Status: early / work in progress.** This is Showcase 1 of the zig-nostr
> roadmap. The current build loads an encrypted (NIP-49) key from disk, connects
> to your relays, and answers NIP-46 requests — `get_public_key`, `sign_event`,
> `ping`, and NIP-44 encrypt/decrypt — behind the connection secret and an
> optional method/event-kind allowlist. A native approval UI is landing later.

## Build

Requires [Zig](https://ziglang.org) 0.16.0.

```sh
zig build
```

## Usage

The signer is configured with environment variables. First create an encrypted
key file — it is stored `0600` as a NIP-49 `ncryptsec`, so your key is never on
disk in the clear:

```sh
# Generates a fresh key (or set SIGNER_SECRET_KEY to import an existing hex key),
# encrypts it, writes the file, and exits.
SIGNER_INIT=1 \
SIGNER_KEY_FILE="$HOME/.zig-nostr-signer.ncryptsec" \
SIGNER_PASSPHRASE="a strong passphrase" \
  zig build run
```

Then start serving:

```sh
SIGNER_KEY_FILE="$HOME/.zig-nostr-signer.ncryptsec" \
SIGNER_PASSPHRASE="a strong passphrase" \
SIGNER_RELAYS="wss://relay.example.com,wss://relay.two" \
SIGNER_CONNECT_SECRET=<optional connection secret> \
  zig build run
```

It decrypts the key once at startup, prints the signer's public key and the
`bunker://` token a client uses to connect, then dials each relay and serves
NIP-46 requests until stopped (reconnecting automatically if a relay drops).
Paste the token into a NIP-46-capable client to sign with a key that never
leaves this process.

For quick local testing you can skip the key file and pass an unencrypted key
directly with `SIGNER_SECRET_KEY=<64-char hex>` — but that keeps the key in your
environment in the clear, so prefer the encrypted file otherwise.

### Restricting what the signer will do

By default the signer honors every NIP-46 request behind the connection secret.
Two optional variables narrow that to least privilege:

- `SIGNER_ALLOWED_METHODS` — comma-separated methods the signer will honor, e.g.
  `get_public_key,sign_event`. `connect`, `ping`, and `logout` are always
  allowed so the handshake can't be locked out. Use this to run a **sign-only**
  bunker that refuses `nip44_decrypt`, so a connected client can't read your DMs
  through it.
- `SIGNER_ALLOWED_KINDS` — comma-separated event kinds `sign_event` may sign,
  e.g. `1,7`. A request to sign any other kind is denied.

Denied requests are answered with a NIP-46 error and logged.

## Roadmap

- [x] `bunker://` connection token from a key + relays
- [x] Relay listen/sign loop (answer NIP-46 requests over a relay)
- [ ] Encrypted key storage at rest (NIP-49 `ncryptsec`)
- [x] Per-request approval policy (method + event-kind allowlists)
- [ ] Native macOS app + downloadable build

## License

MIT © Sepehr Safari
