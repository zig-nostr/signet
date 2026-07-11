//! zig-nostr signer — a headless NIP-46 remote signer ("bunker").
//!
//! Keeps the user's secret key on a machine they control and signs for remote
//! clients over a relay. On startup it loads the key — decrypting an encrypted
//! NIP-49 key file at rest (see `keystore.zig`), or an unencrypted dev key —
//! prints the `bunker://` connection token, then connects to each configured
//! relay and serves NIP-46 requests (see `serve.zig`) until stopped. Requests
//! are authorized by an optional method/event-kind allowlist (see `policy.zig`)
//! behind the connection secret; a native approval UI comes later.

const std = @import("std");
const nostr = @import("nostr");
const serve = @import("serve.zig");
const keystore = @import("keystore.zig");
const policy = @import("policy.zig");

const keys = nostr.keys;
const nip46 = nostr.nip46;
const nip49 = nostr.nip49;
const hex = nostr.hex;

const usage =
    \\zig-nostr signer — headless NIP-46 remote signer (bunker)
    \\
    \\Configure via environment variables:
    \\  SIGNER_KEY_FILE        path to an encrypted (NIP-49) key file
    \\  SIGNER_PASSPHRASE      passphrase for the encrypted key file
    \\  SIGNER_SECRET_KEY      64-char hex secret key (unencrypted; dev use only)
    \\  SIGNER_RELAYS          comma-separated wss:// relay URLs (required to serve)
    \\  SIGNER_CONNECT_SECRET  optional connection secret clients must echo
    \\  SIGNER_ALLOWED_METHODS comma-separated NIP-46 methods to honor (default: all;
    \\                         connect/ping/logout are always allowed)
    \\  SIGNER_ALLOWED_KINDS   comma-separated event kinds sign_event may sign
    \\                         (default: any kind)
    \\  SIGNER_INIT            if set, create/import an encrypted key file and exit
    \\
    \\Provide the key either as an encrypted file (SIGNER_KEY_FILE +
    \\SIGNER_PASSPHRASE, recommended) or as SIGNER_SECRET_KEY (dev only). To create
    \\an encrypted file, run once with SIGNER_INIT set plus SIGNER_KEY_FILE and
    \\SIGNER_PASSPHRASE — it imports SIGNER_SECRET_KEY if present, else generates a
    \\fresh key — then run again without SIGNER_INIT to start serving.
    \\
    \\Prints the signer's public key and the bunker:// token clients connect
    \\with, then serves NIP-46 requests over the relays until stopped.
    \\
;

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    // `SIGNER_INIT` bootstraps an encrypted key file at rest, then exits.
    if (getEnv("SIGNER_INIT") != null) runInit(gpa);

    const relays_env = getEnv("SIGNER_RELAYS") orelse
        fail("set SIGNER_RELAYS to a comma-separated list of wss:// URLs");
    const conn_secret = getEnv("SIGNER_CONNECT_SECRET");

    // Authorization rules, parsed once and shared read-only across relay threads.
    const policy_config = buildPolicyConfig(gpa);

    // Load the secret key once (decrypting the at-rest key file if configured).
    // The deliberately-expensive scrypt KDF runs here and only here; the relay
    // threads below receive the already-derived 32-byte key, so no per-request
    // or per-connection key derivation ever happens.
    const secret_key = loadSecretKey(gpa);

    var signer = keys.Signer.init();
    defer signer.deinit();

    const kp = signer.keyPairFromSecretKey(secret_key) catch
        fail("the configured key is not a valid secp256k1 secret key");

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
        \\zig-nostr signer (headless)
        \\  pubkey : {s}
        \\  bunker : {s}
        \\
        \\Share the bunker:// token with a client to connect. Requests are
        \\auto-approved{s}. Press Ctrl-C to stop.
        \\
    , .{ pk_hex, token, if (conn_secret == null) " (no connection secret set)" else "" });

    // Serve each relay on its own thread. Each thread owns its secp256k1
    // context and bunker, so nothing mutable is shared between them; the only
    // shared state is the read-only key material and the allocator.
    var threads: std.ArrayList(std.Thread) = .empty;
    defer threads.deinit(gpa);
    for (relays.items) |url| {
        const t = std.Thread.spawn(.{}, serveRelayForever, .{ gpa, url, secret_key, conn_secret, &policy_config }) catch |err| {
            std.debug.print("signer: [{s}] could not start: {s}\n", .{ url, @errorName(err) });
            continue;
        };
        try threads.append(gpa, t);
    }
    if (threads.items.len == 0) fail("could not start any relay connections");
    for (threads.items) |t| t.join();
}

/// Connects to `url` and serves requests forever, reconnecting after a short
/// delay whenever the connection drops. Runs on its own thread with its own
/// signing context, derived from the shared read-only `secret_key`.
fn serveRelayForever(
    gpa: std.mem.Allocator,
    url: []const u8,
    secret_key: [32]u8,
    conn_secret: ?[]const u8,
    policy_config: *const policy.Config,
) void {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var signer = keys.Signer.init();
    defer signer.deinit();
    const kp = signer.keyPairFromSecretKey(secret_key) catch {
        std.debug.print("signer: [{s}] invalid secret key\n", .{url});
        return;
    };

    var bunker = nip46.Bunker.initSingleKey(signer, kp, policy_config.policy());
    bunker.secret = conn_secret;

    while (true) {
        serveOnce(gpa, io, url, bunker, kp) catch |err| {
            std.debug.print("signer: [{s}] {s}\n", .{ url, @errorName(err) });
        };
        std.debug.print("signer: [{s}] disconnected; reconnecting in 3s\n", .{url});
        io.sleep(std.Io.Duration.fromSeconds(3), .awake) catch {};
    }
}

/// Dials `url`, then serves requests until the connection closes.
fn serveOnce(
    gpa: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    bunker: nip46.Bunker,
    remote: keys.KeyPair,
) !void {
    var relay = try nostr.relay.dial(gpa, io, url);
    defer relay.deinit();
    std.debug.print("signer: [{s}] connected; listening for NIP-46 requests\n", .{url});
    try serve.serve(gpa, io, relay, bunker, remote);
}

/// Resolves the signer's 32-byte secret key from the environment, preferring
/// the encrypted-at-rest key file over the plaintext `SIGNER_SECRET_KEY`. The
/// scrypt decryption cost is paid once, here, at startup.
fn loadSecretKey(gpa: std.mem.Allocator) [32]u8 {
    if (getEnv("SIGNER_KEY_FILE")) |path| {
        const passphrase = getEnv("SIGNER_PASSPHRASE") orelse
            fail("SIGNER_KEY_FILE is set but SIGNER_PASSPHRASE is not");

        var startup = std.Io.Threaded.init(gpa, .{});
        defer startup.deinit();
        const io = startup.io();

        const ncryptsec = keystore.readKeyFile(gpa, io, std.Io.Dir.cwd(), path) catch |err|
            failFmt("could not read SIGNER_KEY_FILE '{s}': {s}", .{ path, @errorName(err) });
        defer gpa.free(ncryptsec);

        return keystore.decryptKey(gpa, ncryptsec, passphrase) catch
            fail("could not decrypt the key file (wrong SIGNER_PASSPHRASE?)");
    }

    if (getEnv("SIGNER_SECRET_KEY")) |secret_hex| {
        std.debug.print(
            \\warning: SIGNER_SECRET_KEY keeps your key UNENCRYPTED in the environment.
            \\         Prefer an encrypted key file: run once with SIGNER_INIT set plus
            \\         SIGNER_KEY_FILE + SIGNER_PASSPHRASE, then drop SIGNER_SECRET_KEY.
            \\
        , .{});
        return hex.decodeFixed(32, secret_hex) catch
            fail("SIGNER_SECRET_KEY must be exactly 64 hex characters");
    }

    fail("set SIGNER_KEY_FILE (+ SIGNER_PASSPHRASE), or SIGNER_SECRET_KEY (dev only)");
}

/// Creates the encrypted-at-rest key file and exits. Imports `SIGNER_SECRET_KEY`
/// if present (marked known-insecure, since it was plaintext in the environment),
/// otherwise generates a fresh key. Refuses to overwrite an existing file.
fn runInit(gpa: std.mem.Allocator) noreturn {
    const path = getEnv("SIGNER_KEY_FILE") orelse
        fail("SIGNER_INIT requires SIGNER_KEY_FILE (path to write the encrypted key to)");
    const passphrase = getEnv("SIGNER_PASSPHRASE") orelse
        fail("SIGNER_INIT requires SIGNER_PASSPHRASE (to encrypt the key with)");

    var startup = std.Io.Threaded.init(gpa, .{});
    defer startup.deinit();
    const io = startup.io();

    var signer = keys.Signer.init();
    defer signer.deinit();

    var security: nip49.KeySecurity = .known_secure;
    const kp = if (getEnv("SIGNER_SECRET_KEY")) |secret_hex| blk: {
        const secret_key = hex.decodeFixed(32, secret_hex) catch
            fail("SIGNER_SECRET_KEY must be exactly 64 hex characters");
        security = .known_insecure; // it sat in the environment as plaintext
        break :blk signer.keyPairFromSecretKey(secret_key) catch
            fail("SIGNER_SECRET_KEY is not a valid secp256k1 secret key");
    } else signer.generateKeyPair(io) catch |err|
        failFmt("could not generate a key: {s}", .{@errorName(err)});

    const ncryptsec = keystore.encryptKey(gpa, io, kp.secret_key, passphrase, security) catch |err|
        failFmt("could not encrypt the key: {s}", .{@errorName(err)});
    defer gpa.free(ncryptsec);

    keystore.writeNewKeyFile(io, std.Io.Dir.cwd(), path, ncryptsec) catch |err| switch (err) {
        keystore.Error.KeyFileExists => failFmt("SIGNER_KEY_FILE '{s}' already exists; refusing to overwrite", .{path}),
        else => failFmt("could not write '{s}': {s}", .{ path, @errorName(err) }),
    };

    const pk_hex = hex.encode(gpa, &kp.public_key) catch |err|
        failFmt("could not encode the public key: {s}", .{@errorName(err)});
    defer gpa.free(pk_hex);

    std.debug.print(
        \\Initialized encrypted signer key.
        \\  pubkey : {s}
        \\  file   : {s}  (mode 0600, NIP-49 ncryptsec)
        \\
        \\To start serving, unset SIGNER_INIT and run again with SIGNER_KEY_FILE,
        \\SIGNER_PASSPHRASE and SIGNER_RELAYS set.
        \\
    , .{ pk_hex, path });
    std.process.exit(0);
}

/// Parses the authorization allowlists from the environment into a
/// `policy.Config`. Empty/unset variables mean "no restriction"; an unknown
/// method name or a non-numeric kind is a startup error. The returned slices
/// live for the process (shared read-only by every relay thread).
fn buildPolicyConfig(gpa: std.mem.Allocator) policy.Config {
    var cfg = policy.Config{ .gpa = gpa };

    if (getEnv("SIGNER_ALLOWED_METHODS")) |raw| {
        var list: std.ArrayList(nip46.Method) = .empty;
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |item| {
            const name = std.mem.trim(u8, item, " \t");
            if (name.len == 0) continue;
            const method = nip46.Method.fromString(name) orelse
                failFmt("SIGNER_ALLOWED_METHODS: unknown method '{s}'", .{name});
            list.append(gpa, method) catch fail("out of memory building the method allowlist");
        }
        if (list.items.len == 0) list.deinit(gpa) else {
            cfg.allowed_methods = list.toOwnedSlice(gpa) catch fail("out of memory");
        }
    }

    if (getEnv("SIGNER_ALLOWED_KINDS")) |raw| {
        var list: std.ArrayList(u16) = .empty;
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |item| {
            const s = std.mem.trim(u8, item, " \t");
            if (s.len == 0) continue;
            const kind = std.fmt.parseInt(u16, s, 10) catch
                failFmt("SIGNER_ALLOWED_KINDS: invalid kind '{s}'", .{s});
            list.append(gpa, kind) catch fail("out of memory building the kind allowlist");
        }
        if (list.items.len == 0) list.deinit(gpa) else {
            cfg.allowed_kinds = list.toOwnedSlice(gpa) catch fail("out of memory");
        }
    }

    return cfg;
}

fn getEnv(name: [*:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name) orelse return null;
    return std.mem.span(value);
}

fn fail(message: []const u8) noreturn {
    std.debug.print("error: {s}\n\n{s}", .{ message, usage });
    std.process.exit(1);
}

fn failFmt(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("error: ", .{});
    std.debug.print(fmt, args);
    std.debug.print("\n\n{s}", .{usage});
    std.process.exit(1);
}

test {
    // Ensure the serve loop's, keystore's, and policy's hermetic tests run
    // under `zig build test`.
    _ = @import("serve.zig");
    _ = @import("keystore.zig");
    _ = @import("policy.zig");
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
