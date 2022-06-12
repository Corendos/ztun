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
    var stream = try openUdpConnection(address);
    defer {
        stream.close();
    }

    // var buffer: [1024]u8 = undefined;

    // var stream = std.io.fixedBufferStream(&buffer);
    // var writer = stream.writer();
    // _ = writer;

    var buffered_writer = std.io.bufferedWriter(stream.writer());
    var writer = buffered_writer.writer();

    const temp = ztun.Message.Type.fromClassAndMethod(ztun.Message.Class.request, ztun.Message.Method.binding);

    const message_header = ztun.Message.Header{
        .transaction_id = std.crypto.random.int(u96),
        .message_length = 0,
        .@"type" = temp,
    };

    try writer.writeIntBig(u16, @bitCast(u16, message_header.@"type"));
    try writer.writeIntBig(u16, message_header.message_length);
    try writer.writeIntBig(u32, message_header.magic_cookie);
    try writer.writeIntBig(u96, message_header.transaction_id);
    try buffered_writer.flush();

    std.log.debug("Message sent !", .{});

    //    const message_header_raw = @ptrCast(*const [@sizeOf(ztun.Message.Header)]u8, &message_header);

    // try writer.writeStruct(message_header);

    var reader = stream.reader();

    const response_header = ztun.Message.Header{
        .@"type" = @bitCast(ztun.Message.Type, try reader.readIntBig(u16)),
        .message_length = try reader.readIntBig(u16),
        .magic_cookie = try reader.readIntBig(u32),
        .transaction_id = try reader.readIntBig(u96),
    };

    std.log.debug("Response Header: {any}", .{response_header});
}
