const std = @import("std");
const ztun = @import("main.zig");
const IOContext = @import("io.zig").IOContext(void);

pub fn otherFunction() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const socket = try ztun.net.Socket.init(.ipv4, .udp);
    defer socket.deinit();

    const server_address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8888);
    try socket.bind(server_address);

    var buffer: [1024]u8 = undefined;

    const payload = try socket.receiveFrom(&buffer);

    std.log.debug("Received msg from {}: {any}", .{ payload.address, payload.buffer });

    var message_stream = std.io.fixedBufferStream(payload.buffer);
    var message_reader = message_stream.reader();

    const read_result = try ztun.Message.readAlloc(gpa.allocator(), message_reader);
    defer read_result.deinit(gpa.allocator());

    const message: ztun.Message = switch (read_result) {
        .success => |msg| msg,
        .errors => |errors| {
            std.log.err("Got errors: {any}", .{errors});
            return error.InvalidMessage;
        },
    };

    var response = ztun.Message{
        .header = .{
            .@"type" = .{ .class = .success_response, .method = message.header.@"type".method },
            .message_length = 0,
            .transaction_id = message.header.transaction_id,
        },
        .attributes = &[_]ztun.Message.Attribute{
            ztun.Message.Attribute{ .mapped_address = .{
                .address = ztun.attributes.Address{ .v4 = .{ 127, 0, 0, 1 } },
                .port = payload.address.getPort(),
            } },
            ztun.Message.Attribute{ .software = .{ .value = "ztun V0.0.1" } },
        },
    };

    response.header.message_length = @truncate(u16, response.getBodySize());

    std.log.debug("Response is {s}", .{response});

    const response_size = try response.write(std.io.fixedBufferStream(&buffer).writer());

    try socket.sendTo(payload.address, buffer[0..response_size]);
}

fn ioContextRunner(io_context: *IOContext) !void {
    std.log.debug("IOContext loop started", .{});
    try io_context.run();
    std.log.debug("IOContext loop ended", .{});
}

fn initSockets(comptime count: usize) ![count]ztun.net.Socket {
    var sockets: [count]ztun.net.Socket = undefined;

    for (sockets) |*socket, i| {
        socket.* = try ztun.net.Socket.init(.ipv4, .udp);
        const server_address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, @truncate(u16, 8888 + i));
        try socket.bind(server_address);
    }

    return sockets;
}

pub fn main() !void {
    std.log.debug("Creating GPA", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    std.log.debug("Creating IOContext", .{});
    var io_context = try IOContext.init(gpa.allocator());
    defer io_context.deinit();

    // const socket = try ztun.net.Socket.init(.ipv4, .udp);
    // defer socket.deinit();

    // const server_address = std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 8888);
    // try socket.bind(server_address);

    var sockets = try initSockets(4);
    defer {
        for (sockets) |*socket| {
            socket.deinit();
        }
    }

    for (sockets) |*socket| {
        try io_context.registerFd(socket.fd, .{});
    }

    defer {
        for (sockets) |*socket| {
            io_context.unregisterFd(socket.fd) catch unreachable;
        }
    }

    std.log.debug("Starting IOContext thread", .{});
    const io_context_thread = try std.Thread.spawn(.{}, ioContextRunner, .{&io_context});
    defer io_context_thread.join();

    const SLEEP_DURATION = 10;

    std.log.debug("Sleeping {}s...", .{ SLEEP_DURATION });
    std.time.sleep(SLEEP_DURATION * std.time.ns_per_s);

    std.log.debug("Stopping IOContext", .{});
    try io_context.stop();
}
