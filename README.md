# signer

A headless [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md)
remote signer ("bunker") for Nostr, built on the
[zig-nostr/nostr](https://github.com/zig-nostr/nostr) library.

It keeps your `nsec` on a machine you control and signs on behalf of web and
native clients over a relay — the secret key never reaches the client.

> **Status: early / work in progress.** This is Showcase 1 of the zig-nostr
> roadmap. The current build derives your key and prints a `bunker://`
> connection token; the relay listen/sign loop, encrypted key storage
> (NIP-49), and the approval UX are landing next.

## Build

Requires [Zig](https://ziglang.org) 0.16.0.

```sh
zig build
```

## Usage

```sh
SIGNER_SECRET_KEY=<64-char hex secret key> \
  zig build run -- --relay wss://relay.example.com [--relay wss://...] [--secret <connection-secret>]
```

It prints the signer's public key and the `bunker://` token a client uses to
connect.

## Roadmap

- [x] `bunker://` connection token from a key + relays
- [ ] Relay listen/sign loop (answer NIP-46 requests over a relay)
- [ ] Encrypted key storage at rest (NIP-49 `ncryptsec`)
- [ ] Per-request approval policy
- [ ] Native macOS app + downloadable build

## License

MIT © Sepehr Safari
