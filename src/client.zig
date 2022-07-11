const std = @import("std");
const ztun = @import("main.zig");

const Self = @This();

pub const Config = struct {
    address: std.net.Address,
};

allocator: std.mem.Allocator,
config: Config,
socket: ztun.net.Socket,

pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
    const socket = try ztun.net.Socket.init(.ipv4, .udp);
    return Self{
        .allocator = allocator,
        .config = config,
        .socket = socket,
    };
}

pub fn deinit(self: *const Self) void {
    self.socket.deinit();
}

pub fn send(self: *const Self, message: ztun.Message) !bool {
    var buffer: [576]u8 = undefined;

    const message_size = try message.write(std.io.fixedBufferStream(&buffer).writer());
    return try self.socket.sendTo(self.config.address, buffer[0..message_size]);
}

pub fn receiveAlloc(self: *const Self, allocator: std.mem.Allocator) !?ztun.Message {
    const response_buffer: []u8 = blk: {
        var buffer: [576]u8 = undefined;
        if (try self.socket.receiveFrom(&buffer)) |payload| {
            break :blk payload.buffer;
        } else {
            return null;
        }
    };

    std.log.debug("response_buffer is {any}", .{response_buffer});

    const read_result = try ztun.Message.readAlloc(allocator, std.io.fixedBufferStream(response_buffer).reader());
    errdefer read_result.deinit(allocator);

    switch (read_result) {
        .success => |message| return message,
        .errors => return error.InvalidMessage,
    }
}
