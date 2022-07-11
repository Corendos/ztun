const std = @import("std");
const ztun = @import("main.zig");

fn openUdpConnection(address: std.net.Address) anyerror!std.net.Stream {
    var socket = try std.os.socket(address.any.family, std.os.SOCK.DGRAM, std.os.IPPROTO.UDP);
    errdefer {
        std.os.closeSocket(socket);
    }

    try std.os.setsockopt(
        socket,
        std.os.SOL.SOCKET,
        std.os.SO.REUSEADDR,
        &std.mem.toBytes(@as(c_int, 1)),
    );
    var socklen = address.getOsSockLen();

    try std.os.connect(socket, &address.any, socklen);

    return std.net.Stream{ .handle = socket };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8888);
    // const address = std.net.Address.initIp4([4]u8{ 178, 239, 90, 252 }, 3478);
    //const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8888);

    const config = ztun.Client.Config{ .address = address };
    const client = try ztun.Client.init(gpa.allocator(), config);
    defer client.deinit();

    const request = ztun.createBindingRequest(null);

    // Send BIND request
    const result = try client.send(request);
    if (!result) return error.Unexpected;

    // Receive response
    const response = try client.receiveAlloc(gpa.allocator());
    if (response == null) return error.Unexpected;

    defer response.?.deinit(gpa.allocator());

    std.log.debug("{s}", .{response});
}
