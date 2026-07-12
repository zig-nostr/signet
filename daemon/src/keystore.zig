//! Encrypted key storage at rest (NIP-49 `ncryptsec`).
//!
//! The signer never persists the user's secret key in plaintext. This module
//! wraps `nostr.nip49` to turn a 32-byte secret key into an `ncryptsec1...`
//! blob (scrypt + XChaCha20-Poly1305) and back, and to read and write that blob
//! as a `0600` key file.
//!
//! Performance note: the scrypt KDF is deliberately expensive — it is the work
//! factor that guards the key at rest, so it is *not* tuned down for speed. It
//! runs exactly twice in a key's lifetime: once to encrypt at `init` time, once
//! to decrypt at startup. It never runs in the request-serving path, which only
//! ever touches the already-derived 32-byte key.

const std = @import("std");
const nostr = @import("nostr");

const nip49 = nostr.nip49;
const Dir = std.Io.Dir;

/// scrypt cost parameter: 2^16 ≈ 100 ms / 64 MiB, the NIP-49 spec's baseline.
/// Deliberately expensive (it is the at-rest protection) and off the hot path —
/// paid once per encrypt/decrypt, never per request.
pub const default_log_n: u6 = 16;

/// An `ncryptsec` is ~162 chars; cap reads well above that (with slack for a
/// trailing newline) so a wrong path to a large file fails fast instead of
/// being slurped into memory.
pub const max_key_file_bytes = 512;

pub const Error = error{
    /// The key file's contents are not an `ncryptsec1...` token.
    NotAnNcryptsec,
    /// The key file already exists; refusing to overwrite it.
    KeyFileExists,
    /// The key file is empty (or only whitespace).
    EmptyKeyFile,
};

/// Encrypts `secret_key` into a fresh `ncryptsec1...` string at the module's
/// default scrypt cost. `security` records how the key was handled before
/// encryption (NIP-49 metadata). Caller owns the returned string.
pub fn encryptKey(
    gpa: std.mem.Allocator,
    io: std.Io,
    secret_key: [32]u8,
    passphrase: []const u8,
    security: nip49.KeySecurity,
) ![]u8 {
    return nip49.encrypt(gpa, io, secret_key, passphrase, default_log_n, security);
}

/// Decrypts an `ncryptsec1...` string back to the raw 32-byte secret key.
pub fn decryptKey(gpa: std.mem.Allocator, ncryptsec: []const u8, passphrase: []const u8) ![32]u8 {
    return nip49.decrypt(gpa, ncryptsec, passphrase);
}

/// Writes `ncryptsec` into `dir` at `path` as a new `0600` file, refusing to
/// overwrite an existing one so a second `init` can't silently clobber a stored
/// key. `dir` is the containing directory (the process cwd in production).
pub fn writeNewKeyFile(io: std.Io, dir: Dir, path: []const u8, ncryptsec: []const u8) !void {
    dir.writeFile(io, .{
        .sub_path = path,
        .data = ncryptsec,
        .flags = .{
            .exclusive = true,
            .permissions = std.Io.File.Permissions.fromMode(0o600),
        },
    }) catch |err| switch (err) {
        error.PathAlreadyExists => return Error.KeyFileExists,
        else => return err,
    };
}

/// Reads a key file from `dir` and returns the trimmed `ncryptsec1...` token it
/// holds. Caller owns the returned slice.
pub fn readKeyFile(gpa: std.mem.Allocator, io: std.Io, dir: Dir, path: []const u8) ![]u8 {
    const raw = dir.readFileAlloc(io, path, gpa, std.Io.Limit.limited(max_key_file_bytes)) catch |err| switch (err) {
        // A file too big to be an ncryptsec is not a key file.
        error.StreamTooLong => return Error.NotAnNcryptsec,
        else => return err,
    };
    defer gpa.free(raw);

    const token = std.mem.trim(u8, raw, " \t\r\n");
    if (token.len == 0) return Error.EmptyKeyFile;
    if (!std.mem.startsWith(u8, token, "ncryptsec1")) return Error.NotAnNcryptsec;
    return gpa.dupe(u8, token);
}

// ---------------------------------------------------------------------------
// Tests — exercise the new file surface end to end against a real temp dir:
// encrypt a key, write it 0600, read it back, decrypt, and prove the safety
// rails (refuse overwrite, reject non-ncryptsec content).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "writeNewKeyFile then readKeyFile round-trips, is 0600, and refuses overwrite" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const secret = [_]u8{0xab} ** 32;
    const passphrase = "correct horse battery staple";
    const ncryptsec = try encryptKey(gpa, io, secret, passphrase, .known_secure);
    defer gpa.free(ncryptsec);
    try testing.expect(std.mem.startsWith(u8, ncryptsec, "ncryptsec1"));

    try writeNewKeyFile(io, tmp.dir, "key.ncryptsec", ncryptsec);

    // Stored 0600: no group/other permission bits.
    const st = try tmp.dir.statFile(io, "key.ncryptsec", .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0), st.permissions.toMode() & 0o077);

    // Round-trips through the file and decrypts back to the same key.
    const loaded = try readKeyFile(gpa, io, tmp.dir, "key.ncryptsec");
    defer gpa.free(loaded);
    try testing.expectEqualStrings(ncryptsec, loaded);
    const back = try decryptKey(gpa, loaded, passphrase);
    try testing.expectEqualSlices(u8, &secret, &back);

    // A second init must not clobber an existing key file.
    try testing.expectError(Error.KeyFileExists, writeNewKeyFile(io, tmp.dir, "key.ncryptsec", ncryptsec));
}

test "readKeyFile trims surrounding whitespace and rejects non-ncryptsec content" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // A leading/trailing whitespace + newline is trimmed off the token.
    try tmp.dir.writeFile(io, .{ .sub_path = "ok", .data = "  ncryptsec1abcXYZ\n" });
    const tok = try readKeyFile(gpa, io, tmp.dir, "ok");
    defer gpa.free(tok);
    try testing.expectEqualStrings("ncryptsec1abcXYZ", tok);

    // A plaintext hex nsec (anything not starting with `ncryptsec1`) is rejected.
    try tmp.dir.writeFile(io, .{ .sub_path = "bad", .data = "deadbeef" });
    try testing.expectError(Error.NotAnNcryptsec, readKeyFile(gpa, io, tmp.dir, "bad"));

    // An empty / whitespace-only file is rejected too.
    try tmp.dir.writeFile(io, .{ .sub_path = "empty", .data = "   \n" });
    try testing.expectError(Error.EmptyKeyFile, readKeyFile(gpa, io, tmp.dir, "empty"));
}
