//! Signer Approvals — a native desktop approver for a zig-nostr signer.
//!
//! Architecture: the signer daemon (the `daemon/` package in this repo) holds the
//! secret key and does all Nostr work; this app is a *separate process* that
//! approves or denies each request over the daemon's loopback HTTP API, so
//! the key never enters this process. The view lives in `app.native`; this
//! file is the logic (`Model`, `Msg`, `update`).
//!
//! This is the scaffold: it opens the window and renders the shell. Wiring it
//! to the daemon's approval API — poll the queue, approve/deny each request —
//! lands in the next slice.

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

// ------------------------------------------------------------------ model

pub const Msg = union(enum) {
    /// No interaction yet — the daemon wiring (poll, approve, deny) lands in
    /// the next slice. Present so the view has a typed message channel.
    noop,
};

/// Connection lifecycle. Only `.connecting` exists in the scaffold; the
/// daemon wiring adds `.connected` / `.unreachable` / `.unauthorized`.
pub const Phase = enum { connecting };

pub const Model = struct {
    phase: Phase = .connecting,

    /// Human-readable connection state for the shell (bound as `{status}`).
    pub fn status(self: *const Model) []const u8 {
        return switch (self.phase) {
            .connecting => "Connecting to the signer…",
        };
    }
};

pub fn update(model: *Model, msg: Msg) void {
    switch (msg) {
        .noop => {},
    }
    _ = model;
}

// ------------------------------------------------------------------- view

pub const AppUi = canvas.Ui(Msg);
pub const app_markup = @embedFile("app.native");

// -------------------------------------------------------------------- app

const ApprovalsApp = native_sdk.UiApp(Model, Msg);

pub fn initialModel() Model {
    return .{};
}

pub fn main(init: std.process.Init) !void {
    // The app struct (and any real Model) can be multi-MB: `create`
    // heap-allocates and constructs everything in place, so neither ever
    // rides the stack.
    const app_state = try ApprovalsApp.create(std.heap.page_allocator, .{
        .name = "signer-app",
        .scene = shell_scene,
        .canvas_label = canvas_label,
        .update = update,
        .markup = .{ .source = app_markup, .watch_path = "src/app.native", .io = init.io },
    });
    defer app_state.destroy();
    app_state.model = initialModel();

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
