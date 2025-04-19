// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("ztun");
const utils = @import("utils/utils.zig");

pub fn handleMessage(allocator: std.mem.Allocator, socket: std.posix.socket_t, server: *ztun.Server, buffer: []u8) !void {
    // Receive the message in the previously allocated buffer.
    var source: std.net.Address = undefined;
    const raw_message = try utils.receiveFrom(socket, buffer, &source);

    const message = blk: {
        var stream = std.io.fixedBufferStream(raw_message);
        break :blk try ztun.Message.readAlloc(allocator, stream.reader());
    };
    defer message.deinit(allocator);

    const message_result = try server.handleMessage(allocator, message, source);
    // Process the message and return the response if there is one to send.
    switch (message_result) {
        .ok => {},
        .discard => {},
        .response => |response| {
            var stream = std.io.fixedBufferStream(buffer);
            try response.write(stream.writer());
            _ = try utils.sendTo(socket, stream.getWritten(), source);
            response.deinit(allocator);
        },
    }
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    // Parse options from command line.
    const options = try utils.Options.fromArgsAlloc(allocator);

    // Create socket.
    const socket = try std.posix.socket(options.address.any.family, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(socket);

    // Bind socket.
    try std.posix.bind(socket, &options.address.any, options.address.getOsSockLen());

    // Initialize the Server with no authentication.
    var server = ztun.Server.init(allocator, ztun.Server.Options{ .authentication_type = .none });
    defer server.deinit();

    // Allocate the buffer used to receive the requests.
    const buffer = try allocator.alloc(u8, 4096);
    defer allocator.free(buffer);

    // Indefinitely wait for messages.
    while (true) {
        handleMessage(allocator, socket, &server, buffer) catch |err| {
            std.log.err("Unexpected error: {}", .{err});
            continue;
        };
    }
}
