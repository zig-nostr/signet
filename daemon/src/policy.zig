//! Request-authorization policy for the headless signer.
//!
//! The NIP-46 `Bunker` consults an injectable `nip46.Policy` for every request.
//! This module builds one from operator configuration so the signer can follow
//! the principle of least privilege instead of blanket auto-approve: it restricts
//! which key-touching methods are honored, and which event kinds it will sign.
//!
//! The `connect`, `ping`, and `logout` protocol methods are always permitted —
//! rejecting them would only break the client handshake, not protect the key.
//!
//! Performance: the default (unrestricted) config decides in O(1) with no
//! allocation. A configured kind allowlist parses only the event template's
//! `kind` field, only for `sign_event` — off the hot `get_public_key`/`ping`
//! path, and dwarfed by the Schnorr signing a permitted request then triggers.

const std = @import("std");
const nostr = @import("nostr");

const nip46 = nostr.nip46;

/// Operator-configured authorization rules. A null allowlist means "no
/// restriction"; a non-null one is an allowlist. Passed to the policy by
/// pointer as `ctx`, so it must outlive the bunker (it lives for the process).
pub const Config = struct {
    /// Allocator used to parse an event template's kind when `allowed_kinds`
    /// is set; unused when it is null.
    gpa: std.mem.Allocator,
    /// Key-touching methods the signer will honor; null = no restriction.
    /// `connect`/`ping`/`logout` are always allowed regardless.
    allowed_methods: ?[]const nip46.Method = null,
    /// Event kinds the signer will `sign_event` for; null = any kind.
    allowed_kinds: ?[]const u16 = null,

    /// Builds the `nip46.Policy` backed by this config. `self` must outlive the
    /// bunker that holds the returned policy (it is threaded through as `ctx`).
    pub fn policy(self: *const Config) nip46.Policy {
        return .{ .ctx = @constCast(self), .decideFn = &decide };
    }
};

/// Methods that are never restricted: rejecting them would break the NIP-46
/// handshake/liveness, not protect the key.
fn alwaysAllowed(method: nip46.Method) bool {
    return switch (method) {
        .connect, .ping, .logout => true,
        else => false,
    };
}

fn decide(ctx: ?*anyopaque, request: *const nip46.Request) nip46.Decision {
    const cfg: *const Config = @ptrCast(@alignCast(ctx.?));

    // Unknown/unsupported method: fail closed. (The bunker rejects these too,
    // but the policy must never approve something it can't classify.)
    const method = nip46.Method.fromString(request.method) orelse return .reject;

    if (!alwaysAllowed(method)) {
        if (cfg.allowed_methods) |allowed| {
            if (std.mem.indexOfScalar(nip46.Method, allowed, method) == null) return .reject;
        }
    }

    if (method == .sign_event) {
        if (cfg.allowed_kinds) |kinds| {
            const kind = signEventKind(cfg.gpa, request) orelse return .reject;
            if (std.mem.indexOfScalar(u16, kinds, kind) == null) return .reject;
        }
    }

    return .approve;
}

/// Parses the `kind` from a `sign_event` request's event template (params[0]),
/// or null if it is missing or unparseable (the caller treats null as "deny").
pub fn signEventKind(gpa: std.mem.Allocator, request: *const nip46.Request) ?u16 {
    if (request.params.len < 1) return null;
    const parsed = std.json.parseFromSlice(
        struct { kind: u16 },
        gpa,
        request.params[0],
        .{ .ignore_unknown_fields = true },
    ) catch return null;
    defer parsed.deinit();
    return parsed.value.kind;
}

// ---------------------------------------------------------------------------
// Tests — the policy is pure: feed it requests and assert approve/reject.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "default config approves every supported request" {
    var cfg = Config{ .gpa = testing.allocator };
    const p = cfg.policy();

    const gpk = nip46.Request{ .id = "1", .method = "get_public_key", .params = &.{} };
    try testing.expectEqual(nip46.Decision.approve, p.decide(&gpk));

    const tmpl = "{\"kind\":4,\"content\":\"x\",\"tags\":[],\"created_at\":1}";
    const se = nip46.Request{ .id = "2", .method = "sign_event", .params = &[_][]const u8{tmpl} };
    try testing.expectEqual(nip46.Decision.approve, p.decide(&se));
}

test "method allowlist blocks a key-touching method but never connect/ping" {
    const allowed = [_]nip46.Method{ .get_public_key, .sign_event };
    var cfg = Config{ .gpa = testing.allocator, .allowed_methods = &allowed };
    const p = cfg.policy();

    // A sign-only bunker refuses nip44_decrypt so a client can't read the
    // user's DMs through it.
    const dec = nip46.Request{ .id = "1", .method = "nip44_decrypt", .params = &[_][]const u8{ "aa", "bb" } };
    try testing.expectEqual(nip46.Decision.reject, p.decide(&dec));

    // connect/ping are always allowed even though they're not listed.
    const con = nip46.Request{ .id = "2", .method = "connect", .params = &.{} };
    try testing.expectEqual(nip46.Decision.approve, p.decide(&con));
    const png = nip46.Request{ .id = "3", .method = "ping", .params = &.{} };
    try testing.expectEqual(nip46.Decision.approve, p.decide(&png));

    // A listed method still passes.
    const gpk = nip46.Request{ .id = "4", .method = "get_public_key", .params = &.{} };
    try testing.expectEqual(nip46.Decision.approve, p.decide(&gpk));
}

test "kind allowlist gates sign_event by event kind, failing closed" {
    const kinds = [_]u16{1};
    var cfg = Config{ .gpa = testing.allocator, .allowed_kinds = &kinds };
    const p = cfg.policy();

    const note = "{\"kind\":1,\"content\":\"gm\",\"tags\":[],\"created_at\":1}";
    const ok = nip46.Request{ .id = "1", .method = "sign_event", .params = &[_][]const u8{note} };
    try testing.expectEqual(nip46.Decision.approve, p.decide(&ok));

    const del = "{\"kind\":5,\"content\":\"\",\"tags\":[],\"created_at\":1}";
    const no = nip46.Request{ .id = "2", .method = "sign_event", .params = &[_][]const u8{del} };
    try testing.expectEqual(nip46.Decision.reject, p.decide(&no));

    // Unparseable template → deny.
    const junk = nip46.Request{ .id = "3", .method = "sign_event", .params = &[_][]const u8{"not json"} };
    try testing.expectEqual(nip46.Decision.reject, p.decide(&junk));

    // A kind restriction doesn't affect non-signing methods.
    const gpk = nip46.Request{ .id = "4", .method = "get_public_key", .params = &.{} };
    try testing.expectEqual(nip46.Decision.approve, p.decide(&gpk));
}

test "unknown method is rejected" {
    var cfg = Config{ .gpa = testing.allocator };
    const p = cfg.policy();
    const bogus = nip46.Request{ .id = "1", .method = "delete_everything", .params = &.{} };
    try testing.expectEqual(nip46.Decision.reject, p.decide(&bogus));
}
