//! The signer's request-serving loop.
//!
//! Given an established relay connection and a NIP-46 `Bunker`, `serve`
//! subscribes for the kind:24133 requests addressed to the signer, decrypts and
//! dispatches each one through the bunker, and publishes the sealed reply back
//! to the requesting client — the user's key never leaves this process.
//!
//! `serve` is generic over the connection type. In production it drives a live
//! `nostr.relay.Relay`; in tests it drives an in-memory `nostr.relay.Connection`
//! over a scripted fake stream, so the whole request→response cycle is proven
//! hermetically in CI, exactly as the nostr library proves its relay transport.
//! Relay dialing, fan-out across relays, and reconnection live in `main.zig`;
//! this module is the pure protocol loop over one connection.

const std = @import("std");
const nostr = @import("nostr");

const keys = nostr.keys;
const nip46 = nostr.nip46;
const hex = nostr.hex;
const Event = nostr.event.Event;
const Filter = nostr.filter.Filter;
const TagFilter = nostr.filter.TagFilter;

/// The subscription id the signer opens on each relay.
pub const subscription_id = "nostr-signer";

/// Serves NIP-46 requests over `conn` until the connection closes (a clean
/// relay close or EOF), then returns. `conn` is any established connection
/// exposing `subscribe`, `receive`, and `publish` — the live `nostr.relay.Relay`
/// in production, an in-memory `Connection` in tests. `bunker` answers the
/// decrypted requests; `remote` is the signer's communication keypair (the
/// pubkey clients address, and the sender of every reply).
///
/// I/O errors from the relay propagate to the caller (which reconnects);
/// per-request failures (an undecryptable event, a malformed request) are
/// logged and skipped so one bad event can't take the signer down.
pub fn serve(
    gpa: std.mem.Allocator,
    io: std.Io,
    conn: anytype,
    bunker: nip46.Bunker,
    remote: keys.KeyPair,
) !void {
    const my_pubkey_hex = try hex.encode(gpa, &remote.public_key);
    defer gpa.free(my_pubkey_hex);

    // Only requests from now on: ignore any matching history the relay replays
    // before EOSE, so a restart doesn't re-answer stale requests.
    const since = std.Io.Timestamp.now(io, .real).toSeconds();
    const kinds = [_]u16{nip46.kind};
    const p_values = [_][]const u8{my_pubkey_hex};
    const tag_filters = [_]TagFilter{.{ .letter = 'p', .values = &p_values }};
    const filters = [_]Filter{.{ .kinds = &kinds, .tags = &tag_filters, .since = since }};
    try conn.subscribe(subscription_id, &filters);

    while (true) {
        var msg = (try conn.receive()) orelse break;
        defer msg.deinit();
        switch (msg.value) {
            .event => |e| handleRequest(gpa, io, conn, bunker, remote, e.event) catch |err| {
                std.debug.print("signer: dropped a request: {s}\n", .{@errorName(err)});
            },
            .eose => {},
            .closed => |c| {
                std.debug.print("signer: relay closed the subscription: {s}\n", .{c.message});
                return;
            },
            .notice => |n| std.debug.print("signer: relay notice: {s}\n", .{n.message}),
            // OK acks our own reply publications; nothing to do.
            .ok => {},
        }
    }
}

/// Decrypts one kind:24133 request event addressed to us, runs it through the
/// bunker, and publishes the sealed reply back to the event's author.
fn handleRequest(
    gpa: std.mem.Allocator,
    io: std.Io,
    conn: anytype,
    bunker: nip46.Bunker,
    remote: keys.KeyPair,
    request_event: Event,
) !void {
    // The client is the event's author; decrypt with our communication key.
    const plaintext = try nip46.open(gpa, bunker.signer, remote.secret_key, request_event);
    defer gpa.free(plaintext);

    var parsed = try nip46.parseRequest(gpa, plaintext);
    defer parsed.deinit();

    const client_hex = try hex.encode(gpa, &request_event.pubkey);
    defer gpa.free(client_hex);

    var response = try bunker.handle(gpa, io, parsed.value);
    defer response.deinit();

    // Audit line: the request, the client, and the authorization outcome.
    const outcome = if (response.value.err.len == 0) "ok" else response.value.err;
    std.debug.print("signer: {s} '{s}' from {s}…\n", .{ outcome, parsed.value.method, client_hex[0..16] });

    const response_json = try response.value.toJson(gpa);
    defer gpa.free(response_json);

    const created_at = std.Io.Timestamp.now(io, .real).toSeconds();
    var sealed = try nip46.seal(gpa, io, bunker.signer, remote, request_event.pubkey, response_json, created_at);
    defer sealed.deinit();

    try conn.publish(sealed.event);
}

// ---------------------------------------------------------------------------
// Tests — an in-memory fake stream drives a real nostr Connection end to end:
// a client seals a request, the serve loop answers it, and we decrypt the
// published reply and assert on it. No socket, no relay.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A byte stream that hands the serve loop one scripted server frame (then EOF)
/// and captures everything the loop writes back.
const FakeStream = struct {
    to_read: []const u8,
    read_pos: usize = 0,
    written: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    // `pub` because the nostr package's generic `Connection` calls these
    // across the module boundary.
    pub fn read(self: *FakeStream, buffer: []u8) error{}!usize {
        const remaining = self.to_read[self.read_pos..];
        const n = @min(buffer.len, remaining.len);
        @memcpy(buffer[0..n], remaining[0..n]);
        self.read_pos += n;
        return n;
    }

    pub fn writeAll(self: *FakeStream, bytes: []const u8) !void {
        try self.written.appendSlice(self.allocator, bytes);
    }
};

/// Appends an unmasked server text frame (as a relay would send), for any length.
fn appendServerText(list: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    try list.append(allocator, 0x81); // FIN + text
    if (text.len <= 125) {
        try list.append(allocator, @intCast(text.len));
    } else if (text.len <= 0xffff) {
        try list.append(allocator, 126);
        var ext: [2]u8 = undefined;
        std.mem.writeInt(u16, &ext, @intCast(text.len), .big);
        try list.appendSlice(allocator, &ext);
    } else {
        try list.append(allocator, 127);
        var ext: [8]u8 = undefined;
        std.mem.writeInt(u64, &ext, text.len, .big);
        try list.appendSlice(allocator, &ext);
    }
    try list.appendSlice(allocator, text);
}

/// Wraps a NIP-46 request as a relay EVENT frame from `client` to `signer`,
/// runs the serve loop against it, and returns the decrypted reply the loop
/// published. Everything is arena-free; the caller owns `.deinit`.
const Harness = struct {
    signer_ctx: keys.Signer,
    signer_kp: keys.KeyPair,
    client_ctx: keys.Signer,
    client_kp: keys.KeyPair,

    fn init() !Harness {
        const signer_ctx = keys.Signer.init();
        const client_ctx = keys.Signer.init();
        // BIP-340 test-vector secret (known-good) for the signer; a small
        // in-range scalar for the client. Both derive valid x-only pubkeys.
        const signer_sec = try hex.decodeFixed(32, "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef");
        var client_sec = [_]u8{0} ** 32;
        client_sec[31] = 3;
        return .{
            .signer_ctx = signer_ctx,
            .signer_kp = try signer_ctx.keyPairFromSecretKey(signer_sec),
            .client_ctx = client_ctx,
            .client_kp = try client_ctx.keyPairFromSecretKey(client_sec),
        };
    }

    fn deinit(self: *Harness) void {
        self.signer_ctx.deinit();
        self.client_ctx.deinit();
    }

    /// Runs `serve` against a single sealed `request` and returns the reply
    /// plaintext JSON the signer published (decrypted with the client key).
    fn roundTrip(self: *Harness, gpa: std.mem.Allocator, io: std.Io, request: nip46.Request) ![]u8 {
        // Client seals the request to the signer's pubkey.
        const req_json = try request.toJson(gpa);
        defer gpa.free(req_json);
        var sealed_req = try nip46.seal(gpa, io, self.client_ctx, self.client_kp, self.signer_kp.public_key, req_json, 1_700_000_000);
        defer sealed_req.deinit();
        const req_event_json = try nostr.event.toJson(gpa, sealed_req.event);
        defer gpa.free(req_event_json);

        // Frame it as the relay message the subscription would deliver.
        const relay_msg = try std.fmt.allocPrint(gpa, "[\"EVENT\",\"{s}\",{s}]", .{ subscription_id, req_event_json });
        defer gpa.free(relay_msg);
        var script: std.ArrayList(u8) = .empty;
        defer script.deinit(gpa);
        try appendServerText(&script, gpa, relay_msg);

        var written: std.ArrayList(u8) = .empty;
        defer written.deinit(gpa);
        var stream = FakeStream{ .to_read = script.items, .written = &written, .allocator = gpa };
        var conn = nostr.relay.Connection(*FakeStream).init(gpa, io, &stream);
        defer conn.deinit();

        const bunker = nip46.Bunker.initSingleKey(self.signer_ctx, self.signer_kp, nip46.approveAll());
        try serve(gpa, io, &conn, bunker, self.signer_kp);

        // The loop wrote a REQ then an EVENT; find the published EVENT frame and
        // decrypt its content with the client key.
        const reply_event_json = try findPublishedEvent(gpa, written.items);
        defer gpa.free(reply_event_json);
        var reply_event = try nostr.event.fromJson(gpa, reply_event_json);
        defer reply_event.deinit();
        return nip46.open(gpa, self.client_ctx, self.client_kp.secret_key, reply_event.value);
    }
};

/// Scans captured client frames for the `["EVENT",<event>]` publish and returns
/// the inner event JSON object. `written` is mutated in place (frame unmasking).
fn findPublishedEvent(gpa: std.mem.Allocator, written: []u8) ![]u8 {
    var offset: usize = 0;
    while (try nostr.websocket.decodeFrame(written[offset..])) |frame| {
        offset += frame.frame_len;
        const prefix = "[\"EVENT\",";
        if (std.mem.startsWith(u8, frame.payload, prefix)) {
            const inner = frame.payload[prefix.len .. frame.payload.len - 1];
            return gpa.dupe(u8, inner);
        }
    }
    return error.NoPublishedEvent;
}

test "serve answers get_public_key over the relay round-trip" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var h = try Harness.init();
    defer h.deinit();

    const reply = try h.roundTrip(gpa, io, .{ .id = "req-1", .method = "get_public_key", .params = &.{} });
    defer gpa.free(reply);

    var parsed = try nip46.parseResponse(gpa, reply);
    defer parsed.deinit();

    try testing.expectEqualStrings("req-1", parsed.value.id);
    try testing.expectEqualStrings("", parsed.value.err);
    const expected_pubkey = try hex.encode(gpa, &h.signer_kp.public_key);
    defer gpa.free(expected_pubkey);
    try testing.expectEqualStrings(expected_pubkey, parsed.value.result);
}

test "serve signs an event and the signature verifies" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var h = try Harness.init();
    defer h.deinit();

    const template = "{\"kind\":1,\"content\":\"gm from a remote signer\",\"tags\":[],\"created_at\":1700000000}";
    const params = [_][]const u8{template};
    const reply = try h.roundTrip(gpa, io, .{ .id = "sign-1", .method = "sign_event", .params = &params });
    defer gpa.free(reply);

    var parsed = try nip46.parseResponse(gpa, reply);
    defer parsed.deinit();
    try testing.expectEqualStrings("sign-1", parsed.value.id);
    try testing.expectEqualStrings("", parsed.value.err);

    // The result is the signed event; it must carry the signer's key and a
    // signature that verifies against its own recomputed id.
    var signed = try nostr.event.fromJson(gpa, parsed.value.result);
    defer signed.deinit();
    try testing.expectEqual(@as(u16, 1), signed.value.kind);
    try testing.expectEqualStrings("gm from a remote signer", signed.value.content);
    try testing.expectEqualSlices(u8, &h.signer_kp.public_key, &signed.value.pubkey);
    try testing.expect(try nostr.event.verify(gpa, h.signer_ctx, signed.value));
}

test "serve rejects a request when the policy denies it" {
    const gpa = testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var h = try Harness.init();
    defer h.deinit();

    // A bunker that denies everything must still answer — with an error reply.
    const template = "{\"kind\":1,\"content\":\"nope\",\"tags\":[],\"created_at\":1700000000}";
    const params = [_][]const u8{template};

    const req_json = try (nip46.Request{ .id = "deny-1", .method = "sign_event", .params = &params }).toJson(gpa);
    defer gpa.free(req_json);
    var sealed_req = try nip46.seal(gpa, io, h.client_ctx, h.client_kp, h.signer_kp.public_key, req_json, 1_700_000_000);
    defer sealed_req.deinit();
    const req_event_json = try nostr.event.toJson(gpa, sealed_req.event);
    defer gpa.free(req_event_json);
    const relay_msg = try std.fmt.allocPrint(gpa, "[\"EVENT\",\"{s}\",{s}]", .{ subscription_id, req_event_json });
    defer gpa.free(relay_msg);
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try appendServerText(&script, gpa, relay_msg);

    var written: std.ArrayList(u8) = .empty;
    defer written.deinit(gpa);
    var stream = FakeStream{ .to_read = script.items, .written = &written, .allocator = gpa };
    var conn = nostr.relay.Connection(*FakeStream).init(gpa, io, &stream);
    defer conn.deinit();

    const bunker = nip46.Bunker.initSingleKey(h.signer_ctx, h.signer_kp, denyAll());
    try serve(gpa, io, &conn, bunker, h.signer_kp);

    const reply_event_json = try findPublishedEvent(gpa, written.items);
    defer gpa.free(reply_event_json);
    var reply_event = try nostr.event.fromJson(gpa, reply_event_json);
    defer reply_event.deinit();
    const reply = try nip46.open(gpa, h.client_ctx, h.client_kp.secret_key, reply_event.value);
    defer gpa.free(reply);

    var parsed = try nip46.parseResponse(gpa, reply);
    defer parsed.deinit();
    try testing.expectEqualStrings("deny-1", parsed.value.id);
    try testing.expect(parsed.value.err.len > 0);
}

fn denyAllFn(_: ?*anyopaque, _: *const nip46.Request) nip46.Decision {
    return .reject;
}

fn denyAll() nip46.Policy {
    return .{ .decideFn = &denyAllFn };
}
