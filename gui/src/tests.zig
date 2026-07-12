const std = @import("std");
const native_sdk = @import("native_sdk");
const main = @import("main.zig");

const canvas = native_sdk.canvas;
const testing = std.testing;

const AppUi = main.AppUi;
const Model = main.Model;
const Msg = main.Msg;

const AppMarkup = canvas.MarkupView(Model, Msg);

fn buildTree(arena: std.mem.Allocator, model: *const Model) !AppUi.Tree {
    var view = try AppMarkup.init(arena, main.app_markup);
    var ui = AppUi.init(arena);
    const node = view.build(&ui, model) catch |err| {
        // Name the app.native position instead of leaving a bare error
        // trace: the usual causes are a binding without a matching Model
        // field/method or an on-* message without a Msg arm.
        if (err == error.MarkupBuild) {
            std.debug.print("app.native:{d}:{d}: {s}\n", .{ view.diagnostic.line, view.diagnostic.column, view.diagnostic.message });
        }
        return err;
    };
    return ui.finalize(node);
}

fn findByText(widget: canvas.Widget, kind: canvas.WidgetKind, text: []const u8) ?canvas.Widget {
    if (widget.kind == kind and std.mem.eql(u8, widget.text, text)) return widget;
    for (widget.children) |child| {
        if (findByText(child, kind, text)) |found| return found;
    }
    return null;
}

/// A miss fails the test with the mismatch spelled out instead of a
/// null-unwrap panic: the usual cause is app.native and this test drifting
/// apart after an edit.
fn expectByText(widget: canvas.Widget, kind: canvas.WidgetKind, text: []const u8) !canvas.Widget {
    return findByText(widget, kind, text) orelse {
        std.debug.print("no {t} with text \"{s}\" in the view - if you changed app.native, update this test to match\n", .{ kind, text });
        return error.WidgetNotFound;
    };
}

// ------------------------------------------------------------- parsing

test "parseInfo fills the header fields" {
    var m = Model{};
    main.parseInfo(&m, "{\"pubkey\":\"aabbccddeeff00112233\",\"timeout_ms\":120000}");
    try testing.expectEqualStrings("aabbccddeeff00112233", m.pubkey_buf[0..m.pubkey_len]);
    try testing.expectEqual(@as(u64, 120000), m.timeout_ms);
}

test "parsePending loads the queue with kinds and formatted labels" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var m = Model{};
    const body =
        \\{"version":7,"pending":[
        \\  {"id":1,"method":"sign_event","kind":1,"created_at":100},
        \\  {"id":2,"method":"get_public_key","kind":-1,"created_at":200}
        \\]}
    ;
    main.parsePending(&m, body);

    try testing.expectEqual(@as(u64, 7), m.version);
    try testing.expectEqual(@as(usize, 2), m.rows_len);
    try testing.expectEqual(@as(u64, 1), m.rows[0].id);
    try testing.expectEqualStrings("sign_event", m.rows[0].method());
    try testing.expectEqual(@as(i32, 1), m.rows[0].kind);
    try testing.expectEqualStrings("sign_event · kind 1", m.rows[0].label(arena));
    try testing.expectEqualStrings("get_public_key", m.rows[1].label(arena));
}

test "parsePending on an empty queue clears the rows" {
    var m = Model{};
    // Seed a row, then parse an empty queue: it must clear.
    main.parsePending(&m, "{\"version\":1,\"pending\":[{\"id\":9,\"method\":\"ping\",\"kind\":-1,\"created_at\":0}]}");
    try testing.expectEqual(@as(usize, 1), m.rows_len);

    main.parsePending(&m, "{\"version\":3,\"pending\":[]}");
    try testing.expectEqual(@as(usize, 0), m.rows_len);
    try testing.expectEqual(@as(u64, 3), m.version);
}

test "parsePending ignores malformed input, keeping the previous queue" {
    var m = Model{};
    main.parsePending(&m, "{\"version\":2,\"pending\":[{\"id\":5,\"method\":\"sign_event\",\"kind\":4,\"created_at\":0}]}");
    main.parsePending(&m, "not json at all");
    try testing.expectEqual(@as(usize, 1), m.rows_len);
    try testing.expectEqual(@as(u64, 5), m.rows[0].id);
}

test "removeRow drops the matching id and shifts the rest down" {
    var m = Model{};
    main.parsePending(&m,
        \\{"version":1,"pending":[
        \\  {"id":1,"method":"a","kind":-1,"created_at":0},
        \\  {"id":2,"method":"b","kind":-1,"created_at":0},
        \\  {"id":3,"method":"c","kind":-1,"created_at":0}
        \\]}
    );
    m.removeRow(2);
    try testing.expectEqual(@as(usize, 2), m.rows_len);
    try testing.expectEqual(@as(u64, 1), m.rows[0].id);
    try testing.expectEqual(@as(u64, 3), m.rows[1].id);

    m.removeRow(999); // unknown id is a no-op
    try testing.expectEqual(@as(usize, 2), m.rows_len);
}

// ---------------------------------------------------------------- view

test "the empty view shows the connection status and a zero count" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = main.initialModel(); // .connecting, empty queue
    const tree = try buildTree(arena_state.allocator(), &model);

    _ = try expectByText(tree.root, .text, "Signer Approvals");
    _ = try expectByText(tree.root, .text, "Connecting to the signer…");
    _ = try expectByText(tree.root, .status_bar, "0 pending");
}

test "a populated view renders rows and dispatches typed approve/deny" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    var model = Model{};
    model.phase = .connected;
    main.parsePending(&model, "{\"version\":1,\"pending\":[{\"id\":42,\"method\":\"sign_event\",\"kind\":1,\"created_at\":0}]}");

    const tree = try buildTree(arena_state.allocator(), &model);

    _ = try expectByText(tree.root, .text, "sign_event · kind 1");
    _ = try expectByText(tree.root, .status_bar, "1 pending");

    // The Approve/Deny bindings carry the row id in the typed message.
    const approve = try expectByText(tree.root, .button, "Approve");
    switch (tree.msgForPointer(approve.id, .up).?) {
        .approve => |id| try testing.expectEqual(@as(u64, 42), id),
        else => return error.WrongMessage,
    }

    const deny = try expectByText(tree.root, .button, "Deny");
    switch (tree.msgForPointer(deny.id, .up).?) {
        .reject => |id| try testing.expectEqual(@as(u64, 42), id),
        else => return error.WrongMessage,
    }
}
