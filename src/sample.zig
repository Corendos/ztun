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

    const address = std.net.Address.initIp4([4]u8{ 178, 239, 90, 252 }, 3478);
    //const address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8888);
    var network_stream = try openUdpConnection(address);
    defer {
        network_stream.close();
    }

    const request = ztun.Request{
        .header = ztun.message.Header{
            .@"type" = ztun.message.Type{
                .class = ztun.message.Class.request,
                .method = ztun.message.Method.binding,
            },
            .transaction_id = std.crypto.random.int(u96),
        },
        .attributes = &.{},
    };

    // Send BIND request
    try ztun.sendRequest(request, network_stream);

    // Receive response
    const response = try ztun.receiveResponse(gpa.allocator(), network_stream);
    defer response.deinit(gpa.allocator());

    if (response.header.transaction_id != request.header.transaction_id) return error.InvalidTransactionId;

    std.log.debug("{s}", .{response.attributes});
}
