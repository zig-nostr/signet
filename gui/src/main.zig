//! Signer Approvals — a native desktop approver for a zig-nostr signer.
//!
//! Architecture: the signer daemon (the daemon/ package in this repo) holds the
//! secret key and does all Nostr work; this app is a *separate process* that
//! approves or denies each request over the daemon's loopback HTTP API, so
//! the key never enters this process. This app only ever sees request
//! metadata and sends back a yes/no.
//!
//! Two ways to run:
//!
//!  - **Attached** (default): the daemon is already running; the app connects
//!    to its approval API at `SIGNER_APPROVAL_HTTP`.
//!  - **Managed** (`SIGNER_BIN` set): the app *spawns and supervises* the
//!    daemon binary as a child process — one launch brings up both. The child
//!    inherits this process's environment (so it gets `SIGNER_KEY_FILE`,
//!    `SIGNER_PASSPHRASE`, `SIGNER_RELAYS`, `SIGNER_APPROVAL_HTTP`,
//!    `SIGNER_APPROVAL_TOKEN_FILE`), and the runtime kills it when the app
//!    quits, so no daemon is orphaned holding the approval port. The key still
//!    only ever lives in the daemon child.
//!
//! The view lives in `app.native`; this file is the logic. All I/O is through
//! the Native SDK effects channel (`fx.spawn` supervises the daemon, `fx.fetch`
//! talks HTTP, `fx.readFile` reads the token, `fx.startTimer` backs off), so
//! `update` stays a pure state transition and the view stays declarative.

const std = @import("std");
const runner = @import("runner");
const native_sdk = @import("native_sdk");

pub const panic = std.debug.FullPanic(native_sdk.debug.capturePanic);

const canvas = native_sdk.canvas;
const geometry = native_sdk.geometry;

const canvas_label = "main-canvas";
const window_width: f32 = 460;
const window_height: f32 = 560;

const app_permissions = [_][]const u8{ native_sdk.security.permission_command, native_sdk.security.permission_view };
const shell_views = [_]native_sdk.ShellView{
    .{ .label = canvas_label, .kind = .gpu_surface, .fill = true, .role = "Approvals canvas", .accessibility_label = "Approvals", .gpu_backend = .metal, .gpu_pixel_format = .bgra8_unorm, .gpu_present_mode = .timer, .gpu_alpha_mode = .@"opaque", .gpu_color_space = .srgb, .gpu_vsync = true },
};
const shell_windows = [_]native_sdk.ShellWindow{.{
    .label = "main",
    .title = "Signer Approvals",
    .width = window_width,
    .height = window_height,
    .restore_state = false,
    .views = &shell_views,
}};
const shell_scene: native_sdk.ShellConfig = .{ .windows = &shell_windows };

// ------------------------------------------------------------- config

const default_address = "127.0.0.1:8787";
const default_token_file = ".zig-nostr-signer.token";

// Effect keys. Fetch/spawn/file effects share one key space and 16 slots; the
// long-lived daemon spawn holds one slot for the process's lifetime. Timer
// keys are their own namespace. Decisions use a small pool so several can be
// in flight at once (a fast double-approve never collides on one key).
const daemon_key: u64 = 1;
const token_key: u64 = 2;
const info_key: u64 = 3;
const pending_key: u64 = 4;
const decision_key_base: u64 = 8;
const decision_key_slots: u64 = 8;
const retry_timer_key: u64 = 100;

fn decisionKey(id: u64) u64 {
    return decision_key_base + (id % decision_key_slots);
}

// ------------------------------------------------------------------ model

/// One pending signing request awaiting the operator's decision. Strings are
/// copied into fixed buffers so a row never aliases a fetch response body
/// (which is only valid during the `update` call that delivers it).
pub const Row = struct {
    id: u64 = 0,
    method_buf: [24]u8 = [_]u8{0} ** 24,
    method_len: u8 = 0,
    /// Event kind for `sign_event`, else -1.
    kind: i32 = -1,
    created_at: i64 = 0,

    pub fn method(self: *const Row) []const u8 {
        return self.method_buf[0..self.method_len];
    }

    pub fn setMethod(self: *Row, m: []const u8) void {
        const n = @min(m.len, self.method_buf.len);
        @memcpy(self.method_buf[0..n], m[0..n]);
        self.method_len = @intCast(n);
    }

    /// One-line label for the row, e.g. "sign_event · kind 1" or
    /// "get_public_key". Formats into the build arena.
    pub fn label(self: *const Row, arena: std.mem.Allocator) []const u8 {
        if (self.kind >= 0) {
            return std.fmt.allocPrint(arena, "{s} · kind {d}", .{ self.method(), self.kind }) catch self.method();
        }
        return self.method();
    }
};

/// Connection / supervision lifecycle, shown in the header.
pub const Phase = enum {
    /// Managed mode: the daemon child is starting and we do not have a working
    /// token / connection yet.
    starting,
    /// Attached mode: trying to reach an already-running daemon.
    connecting,
    connected,
    /// Was reachable, now failing — retrying.
    disconnected,
    /// The API rejected our bearer token (attached mode).
    unauthorized,
    /// Managed mode: the daemon child exited; awaiting a manual restart.
    daemon_exited,
};

pub const max_pending = 32; // matches the daemon broker's capacity

pub const Model = struct {
    // Resolved at boot from the environment; stable for the process.
    base_url_buf: [96]u8 = [_]u8{0} ** 96,
    base_url_len: usize = 0,
    token_path_buf: [512]u8 = [_]u8{0} ** 512,
    token_path_len: usize = 0,
    daemon_bin_buf: [512]u8 = [_]u8{0} ** 512,
    daemon_bin_len: usize = 0,
    /// True when `SIGNER_BIN` is set: the app spawns and supervises the daemon.
    managed: bool = false,

    // Read from the token file via `fx.readFile`; the bearer header value.
    auth_buf: [96]u8 = [_]u8{0} ** 96,
    auth_len: usize = 0,

    phase: Phase = .connecting,
    pubkey_buf: [64]u8 = [_]u8{0} ** 64,
    pubkey_len: usize = 0,
    timeout_ms: u64 = 0,
    /// Short human note for the `.daemon_exited` state, e.g. "signer exited
    /// (code 1)".
    exit_note_buf: [64]u8 = [_]u8{0} ** 64,
    exit_note_len: usize = 0,

    rows: [max_pending]Row = [_]Row{.{}} ** max_pending,
    rows_len: usize = 0,
    /// The daemon's queue version; sent back as `?since=` so a poll returns
    /// as soon as the queue changes.
    version: u64 = 0,

    // -- config accessors --

    pub fn setBaseUrl(self: *Model, host_port: []const u8) void {
        const s = std.fmt.bufPrint(&self.base_url_buf, "http://{s}", .{host_port}) catch return;
        self.base_url_len = s.len;
    }
    pub fn baseUrl(self: *const Model) []const u8 {
        return self.base_url_buf[0..self.base_url_len];
    }
    pub fn setTokenPath(self: *Model, path: []const u8) void {
        const n = @min(path.len, self.token_path_buf.len);
        @memcpy(self.token_path_buf[0..n], path[0..n]);
        self.token_path_len = n;
    }
    pub fn tokenPath(self: *const Model) []const u8 {
        return self.token_path_buf[0..self.token_path_len];
    }
    pub fn setDaemonBin(self: *Model, path: []const u8) void {
        const n = @min(path.len, self.daemon_bin_buf.len);
        @memcpy(self.daemon_bin_buf[0..n], path[0..n]);
        self.daemon_bin_len = n;
    }
    pub fn daemonBin(self: *const Model) []const u8 {
        return self.daemon_bin_buf[0..self.daemon_bin_len];
    }
    pub fn setAuth(self: *Model, token: []const u8) void {
        if (token.len == 0) {
            self.auth_len = 0;
            return;
        }
        const s = std.fmt.bufPrint(&self.auth_buf, "Bearer {s}", .{token}) catch return;
        self.auth_len = s.len;
    }
    pub fn auth(self: *const Model) []const u8 {
        return self.auth_buf[0..self.auth_len];
    }
    pub fn hasToken(self: *const Model) bool {
        return self.auth_len > 0;
    }

    // -- view bindings --

    /// The pending queue, iterated by `<for each="visible">`.
    pub fn visible(self: *const Model, arena: std.mem.Allocator) []const Row {
        _ = arena;
        return self.rows[0..self.rows_len];
    }
    pub fn count(self: *const Model) usize {
        return self.rows_len;
    }
    /// Body states — exactly one is true, so the view renders three plain
    /// `<if>` blocks instead of nested else chains.
    pub fn daemon_down(self: *const Model) bool {
        return self.phase == .daemon_exited;
    }
    pub fn show_empty(self: *const Model) bool {
        return self.phase != .daemon_exited and self.rows_len == 0;
    }
    pub fn show_queue(self: *const Model) bool {
        return self.phase != .daemon_exited and self.rows_len > 0;
    }

    /// Connection state line in the header.
    pub fn status(self: *const Model) []const u8 {
        return switch (self.phase) {
            .starting => "Starting the signer…",
            .connecting => "Connecting to the signer…",
            .connected => "Connected",
            .disconnected => "Signer unreachable — retrying…",
            .unauthorized => "Unauthorized — check the token file",
            .daemon_exited => "Signer stopped",
        };
    }

    /// Message shown in the body while the queue is empty.
    pub fn empty_text(self: *const Model) []const u8 {
        return switch (self.phase) {
            .connected => "No pending requests",
            .starting => "Starting the signer…",
            .connecting => "Connecting to the signer…",
            .disconnected => "Signer unreachable — retrying…",
            .unauthorized => "Unauthorized — check the token file",
            .daemon_exited => "Signer stopped",
        };
    }

    pub fn exit_note(self: *const Model) []const u8 {
        if (self.exit_note_len == 0) return "The signer process stopped.";
        return self.exit_note_buf[0..self.exit_note_len];
    }

    /// Abbreviated signer public key for the header (`aabbccddee…11223344`).
    pub fn pubkey_short(self: *const Model, arena: std.mem.Allocator) []const u8 {
        const pk = self.pubkey_buf[0..self.pubkey_len];
        if (pk.len == 0) return "not connected";
        if (pk.len <= 20) return pk;
        return std.fmt.allocPrint(arena, "{s}…{s}", .{ pk[0..10], pk[pk.len - 8 ..] }) catch pk[0..20];
    }

    fn setPubkey(self: *Model, pk: []const u8) void {
        const n = @min(pk.len, self.pubkey_buf.len);
        @memcpy(self.pubkey_buf[0..n], pk[0..n]);
        self.pubkey_len = n;
    }

    fn setExitNote(self: *Model, exit: native_sdk.EffectExit) void {
        const s = switch (exit.reason) {
            .spawn_failed, .rejected => std.fmt.bufPrint(&self.exit_note_buf, "The signer failed to start — check SIGNER_BIN.", .{}),
            .signaled => std.fmt.bufPrint(&self.exit_note_buf, "The signer was terminated (signal).", .{}),
            else => std.fmt.bufPrint(&self.exit_note_buf, "The signer exited (code {d}).", .{exit.code}),
        } catch return;
        self.exit_note_len = s.len;
    }

    pub fn clearRows(self: *Model) void {
        self.rows_len = 0;
    }

    pub fn removeRow(self: *Model, id: u64) void {
        var i: usize = 0;
        while (i < self.rows_len) : (i += 1) {
            if (self.rows[i].id == id) {
                var j = i;
                while (j + 1 < self.rows_len) : (j += 1) self.rows[j] = self.rows[j + 1];
                self.rows_len -= 1;
                return;
            }
        }
    }
};

// -------------------------------------------------------------------- msg

pub const Msg = union(enum) {
    daemon_line: native_sdk.EffectLine,
    daemon_exited: native_sdk.EffectExit,
    token_read: native_sdk.EffectFileResult,
    info: native_sdk.EffectResponse,
    pending: native_sdk.EffectResponse,
    decided: native_sdk.EffectResponse,
    tick: native_sdk.EffectTimer,
    approve: u64,
    reject: u64,
    restart,
};

// ---------------------------------------------------------------- effects

pub const AppUi = canvas.Ui(Msg);
pub const app_markup = @embedFile("app.native");

const ApprovalsApp = native_sdk.UiApp(Model, Msg);
const Effects = ApprovalsApp.Effects;

fn spawnDaemon(model: *Model, fx: *Effects) void {
    model.phase = .starting;
    fx.spawn(.{
        .key = daemon_key,
        .argv = &.{model.daemonBin()},
        .on_line = Effects.lineMsg(.daemon_line),
        .on_exit = Effects.exitMsg(.daemon_exited),
    });
}

/// One connection attempt: (re-)read the token file, then poll. Re-reading on
/// every attempt means a freshly (re)started daemon's new token is always
/// picked up, healing both the initial startup race and a restart.
fn attemptConnect(model: *Model, fx: *Effects) void {
    if (model.tokenPath().len == 0) {
        // No token file configured at all: nothing to authenticate with.
        model.phase = .unauthorized;
        return;
    }
    fx.readFile(.{
        .key = token_key,
        .path = model.tokenPath(),
        .on_result = Effects.fileMsg(.token_read),
    });
}

fn startPolling(model: *Model, fx: *Effects) void {
    fetchInfo(model, fx);
    pollPending(model, fx);
}

fn fetchInfo(model: *Model, fx: *Effects) void {
    var buf: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&buf, "{s}/info", .{model.baseUrl()}) catch return;
    const headers = [_]std.http.Header{.{ .name = "authorization", .value = model.auth() }};
    fx.fetch(.{
        .key = info_key,
        .url = url,
        .headers = &headers,
        .timeout_ms = 5_000,
        .on_response = Effects.responseMsg(.info),
    });
}

fn pollPending(model: *Model, fx: *Effects) void {
    var buf: [160]u8 = undefined;
    const url = std.fmt.bufPrint(&buf, "{s}/pending?since={d}", .{ model.baseUrl(), model.version }) catch return;
    const headers = [_]std.http.Header{.{ .name = "authorization", .value = model.auth() }};
    // The daemon long-polls ~1s before answering; 35s is generous headroom.
    fx.fetch(.{
        .key = pending_key,
        .url = url,
        .headers = &headers,
        .timeout_ms = 35_000,
        .on_response = Effects.responseMsg(.pending),
    });
}

fn sendDecision(model: *Model, fx: *Effects, id: u64, approve: bool) void {
    var url_buf: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}/decision", .{model.baseUrl()}) catch return;
    var body_buf: [64]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"id\":{d},\"decision\":\"{s}\"}}", .{ id, if (approve) "approve" else "reject" }) catch return;
    const headers = [_]std.http.Header{
        .{ .name = "authorization", .value = model.auth() },
        .{ .name = "content-type", .value = "application/json" },
    };
    fx.fetch(.{
        .key = decisionKey(id),
        .method = .POST,
        .url = url,
        .headers = &headers,
        .body = body,
        .timeout_ms = 5_000,
        .on_response = Effects.responseMsg(.decided),
    });
}

fn armRetry(fx: *Effects) void {
    fx.startTimer(.{
        .key = retry_timer_key,
        .interval_ms = 2_000,
        .mode = .one_shot,
        .on_fire = Effects.timerMsg(.tick),
    });
}

/// A poll came back unauthorized. In managed mode the daemon may have just
/// (re)written its token, so drop ours and re-acquire on the next tick; in
/// attached mode it is a real misconfiguration.
fn onUnauthorized(model: *Model, fx: *Effects) void {
    if (model.managed) {
        model.setAuth("");
        model.phase = .starting;
    } else {
        model.phase = .unauthorized;
    }
    armRetry(fx);
}

/// Boot command: in managed mode spawn the daemon; either way begin connecting.
pub fn boot(model: *Model, fx: *Effects) void {
    if (model.managed) {
        spawnDaemon(model, fx);
    } else {
        model.phase = .connecting;
    }
    attemptConnect(model, fx);
}

pub fn update(model: *Model, msg: Msg, fx: *Effects) void {
    switch (msg) {
        .daemon_line => {}, // daemon stdout; the connection state is the signal we surface

        .daemon_exited => |exit| {
            // A cancel we initiated (restart / app quit) reports `.cancelled` —
            // that is expected teardown, not a crash to report.
            if (exit.reason == .cancelled) return;
            model.phase = .daemon_exited;
            model.setExitNote(exit);
            model.setAuth("");
            model.clearRows();
        },

        .token_read => |r| switch (r.outcome) {
            .ok => {
                const token = std.mem.trim(u8, r.bytes, " \t\r\n");
                if (token.len > 0) {
                    model.setAuth(token);
                    if (model.phase != .connected) model.phase = .connecting;
                    startPolling(model, fx);
                } else {
                    armRetry(fx); // empty file — the daemon has not written it yet
                }
            },
            // Not there yet (managed daemon still starting) or unreadable: retry.
            else => armRetry(fx),
        },

        .info => |r| {
            if (r.outcome == .ok and r.status == 200) {
                parseInfo(model, r.body);
            } else if (r.outcome == .ok and r.status == 401) {
                onUnauthorized(model, fx);
            }
            // Otherwise best-effort: the /pending poll owns the phase.
        },

        .pending => |r| switch (r.outcome) {
            .ok => switch (r.status) {
                200 => {
                    model.phase = .connected;
                    parsePending(model, r.body);
                    pollPending(model, fx); // re-arm the long-poll chain
                },
                401 => onUnauthorized(model, fx),
                else => {
                    model.phase = .disconnected;
                    armRetry(fx);
                },
            },
            // Never started (momentary duplicate key) or a transport failure:
            // fall back to a timed reconnect (which re-reads the token).
            .rejected => armRetry(fx),
            else => {
                if (model.phase == .connected) model.phase = .disconnected;
                armRetry(fx);
            },
        },

        // The poll chain reflects the removal; nothing else to do on ack.
        .decided => {},

        .tick => |t| {
            if (t.outcome != .fired) return;
            if (model.phase == .daemon_exited) return; // wait for the Restart button
            // A full reconnect attempt: re-read the token, then poll.
            attemptConnect(model, fx);
        },

        .approve => |id| {
            sendDecision(model, fx, id, true);
            model.removeRow(id); // optimistic; a poll re-adds it if the send failed
        },
        .reject => |id| {
            sendDecision(model, fx, id, false);
            model.removeRow(id);
        },

        .restart => {
            if (!model.managed) return;
            model.setAuth("");
            model.clearRows();
            spawnDaemon(model, fx);
            attemptConnect(model, fx);
        },
    }
}

// -------------------------------------------------------- response parsing

/// Fills `model` from a `GET /info` body: `{"pubkey":..,"timeout_ms":..}`.
/// Malformed input is ignored (the header simply stays as it was).
pub fn parseInfo(model: *Model, body: []const u8) void {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const Info = struct { pubkey: []const u8 = "", timeout_ms: u64 = 0 };
    const parsed = std.json.parseFromSliceLeaky(Info, fba.allocator(), body, .{ .ignore_unknown_fields = true }) catch return;
    model.setPubkey(parsed.pubkey);
    model.timeout_ms = parsed.timeout_ms;
}

/// Replaces the queue from a `GET /pending` body:
/// `{"version":N,"pending":[{"id":,"method":,"kind":,"created_at":},..]}`.
/// Malformed input leaves the previous queue untouched.
pub fn parsePending(model: *Model, body: []const u8) void {
    var buf: [16 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const Pending = struct {
        version: u64 = 0,
        pending: []const struct {
            id: u64 = 0,
            method: []const u8 = "",
            kind: i32 = -1,
            created_at: i64 = 0,
        } = &.{},
    };
    const parsed = std.json.parseFromSliceLeaky(Pending, fba.allocator(), body, .{ .ignore_unknown_fields = true }) catch return;

    model.version = parsed.version;
    var n: usize = 0;
    for (parsed.pending) |p| {
        if (n >= max_pending) break;
        var row = Row{ .id = p.id, .kind = p.kind, .created_at = p.created_at };
        row.setMethod(p.method);
        model.rows[n] = row;
        n += 1;
    }
    model.rows_len = n;
}

// -------------------------------------------------------------------- app

pub fn initialModel() Model {
    return .{};
}

/// Resolves the daemon address, token-file path, and (optional) daemon binary
/// from the environment. `SIGNER_APPROVAL_HTTP` defaults to 127.0.0.1:8787;
/// the token-file path defaults to `$HOME/.zig-nostr-signer.token`; setting
/// `SIGNER_BIN` switches on managed mode (the app supervises that binary). The
/// token *contents* are read later through the effects channel, so a managed
/// daemon that writes the file after we launch is picked up on retry.
fn loadConfig(model: *Model, environ: *const std.process.Environ.Map) void {
    const address = environ.get("SIGNER_APPROVAL_HTTP") orelse default_address;
    model.setBaseUrl(address);

    if (environ.get("SIGNER_BIN")) |bin| {
        model.setDaemonBin(bin);
        model.managed = true;
    }

    if (environ.get("SIGNER_APPROVAL_TOKEN_FILE")) |path| {
        model.setTokenPath(path);
    } else if (environ.get("HOME")) |home| {
        var buf: [512]u8 = undefined;
        if (std.fmt.bufPrint(&buf, "{s}/{s}", .{ home, default_token_file })) |path| {
            model.setTokenPath(path);
        } else |_| {}
    }
}

pub fn main(init: std.process.Init) !void {
    const app_state = try ApprovalsApp.create(std.heap.page_allocator, .{
        .name = "signer-app",
        .scene = shell_scene,
        .canvas_label = canvas_label,
        .init_fx = boot,
        .update_fx = update,
        .markup = .{ .source = app_markup, .watch_path = "src/app.native", .io = init.io },
    });
    defer app_state.destroy();
    app_state.model = initialModel();
    loadConfig(&app_state.model, init.environ_map);

    try runner.runWithOptions(app_state.app(), .{
        .app_name = "signer-app",
        .window_title = "Signer Approvals",
        .bundle_id = "com.zig-nostr.signer-app",
        .icon_path = "assets/icon.png",
        .default_frame = geometry.RectF.init(0, 0, window_width, window_height),
        .restore_state = false,
        .js_window_api = false,
        .security = .{
            .permissions = &app_permissions,
            .navigation = .{ .allowed_origins = &.{ "zero://inline", "zero://app" } },
        },
    }, init);
}

test {
    _ = @import("tests.zig");
}
