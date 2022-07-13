const std = @import("std");
const ztun = @import("main.zig");

pub fn killSwitchFn(server: *ztun.Server) void {
    std.time.sleep(20 * std.time.ns_per_s);
    server.stop() catch {};
}

pub fn main() !void {
    std.log.debug("Creating GPA", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8888);
    var server = try ztun.Server.init(gpa.allocator(), .{ .address = address });
    defer server.deinit();

    var killSwitchThread = try std.Thread.spawn(.{}, killSwitchFn, .{&server});
    defer killSwitchThread.join();

    try server.run();
}
