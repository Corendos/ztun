const std = @import("std");
const testing = std.testing;

pub const Message = @import("message.zig");
pub const attributes = @import("attributes.zig");
pub const Server = @import("server.zig");
pub const Client = @import("client.zig");
pub const net = @import("net.zig");

pub const MAGIC_COOKIE = 0x2112A442;

pub fn createBindingRequest(transaction_id: ?u96) Message {
    return Message{
        .header = .{
            .@"type" = .{ .class = .request, .method = .binding },
            .message_length = 0,
            .transaction_id = transaction_id orelse std.crypto.random.int(u96),
        },
        .attributes = &.{},
    };
}