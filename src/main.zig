//! zig-nostr signer — a headless NIP-46 remote signer ("bunker").
//!
//! Keeps the user's secret key on a machine they control and signs for remote
//! clients over a relay. This early build derives the key and prints the
//! `bunker://` connection token; the relay listen/sign loop, encrypted key
//! storage (NIP-49), and the approval UX are the next slices — see README.

const std = @import("std");
const nostr = @import("nostr");

const keys = nostr.keys;
const nip46 = nostr.nip46;
const hex = nostr.hex;

const usage =
    \\zig-nostr signer — headless NIP-46 remote signer (bunker)
    \\
    \\Configure via environment variables:
    \\  SIGNER_SECRET_KEY      64-char hex secret key (required)
    \\  SIGNER_RELAYS          comma-separated wss:// relay URLs (required)
    \\  SIGNER_CONNECT_SECRET  optional connection secret
    \\
    \\Prints the signer's public key and the bunker:// token clients connect with.
    \\
;

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    const secret_hex = getEnv("SIGNER_SECRET_KEY") orelse
        fail("set SIGNER_SECRET_KEY to a 64-char hex secret key");
    const relays_env = getEnv("SIGNER_RELAYS") orelse
        fail("set SIGNER_RELAYS to a comma-separated list of wss:// URLs");
    const conn_secret = getEnv("SIGNER_CONNECT_SECRET");

    const secret_key = hex.decodeFixed(32, secret_hex) catch
        fail("SIGNER_SECRET_KEY must be exactly 64 hex characters");

    var signer = keys.Signer.init();
    defer signer.deinit();

    const kp = signer.keyPairFromSecretKey(secret_key) catch
        fail("SIGNER_SECRET_KEY is not a valid secp256k1 secret key");

    var relays: std.ArrayList([]const u8) = .empty;
    defer relays.deinit(gpa);
    var it = std.mem.splitScalar(u8, relays_env, ',');
    while (it.next()) |raw| {
        const url = std.mem.trim(u8, raw, " \t");
        if (url.len != 0) try relays.append(gpa, url);
    }
    if (relays.items.len == 0) fail("SIGNER_RELAYS contained no relay URLs");

    const token = try nip46.buildBunkerUri(gpa, kp.public_key, relays.items, conn_secret);
    defer gpa.free(token);

    const pk_hex = try hex.encode(gpa, &kp.public_key);
    defer gpa.free(pk_hex);

    std.debug.print(
        \\zig-nostr signer (headless, work in progress)
        \\  pubkey : {s}
        \\  bunker : {s}
        \\
        \\The relay listen/sign loop is not wired up yet — this prints the
        \\connection token so clients can be wired while it lands.
        \\
    , .{ pk_hex, token });
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    return std.mem.span(value);
}

fn fail(message: []const u8) noreturn {
    std.debug.print("error: {s}\n\n{s}", .{ message, usage });
    std.process.exit(1);
}

test "derives the pubkey and builds a bunker token" {
    const gpa = std.testing.allocator;
    var signer = keys.Signer.init();
    defer signer.deinit();

    // BIP-340 test vector: this secret key derives this x-only public key.
    const secret = try hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
    const kp = try signer.keyPairFromSecretKey(secret);

    const relays = [_][]const u8{"wss://relay.example.com"};
    const token = try nip46.buildBunkerUri(gpa, kp.public_key, &relays, "s3cret");
    defer gpa.free(token);

    try std.testing.expectStringStartsWith(
        token,
        "bunker://dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659?",
    );
    try std.testing.expect(std.mem.indexOf(u8, token, "secret=s3cret") != null);
}
