// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("ztun");
const utils = @import("utils.zig");

const linux = std.os.linux;

pub fn createAndBindSocket() !i32 {
    // This will be used in a dual-stack mode.
    const ipv6_bind_address = ztun.net.Address{ .ipv6 = try ztun.net.Ipv6Address.parse("::", 3478) };

    var ipv6_socket = try utils.createSocket(.ipv6);
    try utils.bindSocket(ipv6_socket, ipv6_bind_address);

    return ipv6_socket;
}

pub fn handleMessage(fd: i32, server: *ztun.Server, buffer: []u8, allocator: std.mem.Allocator) !void {
    // Receive the message in the previously allocated buffer.
    const raw_message = try utils.receiveFrom(fd, buffer);

    const message = blk: {
        var stream = std.io.fixedBufferStream(raw_message.data);
        break :blk try ztun.Message.readAlloc(stream.reader(), allocator);
    };
    defer message.deinit(allocator);

    const message_result = try server.handleMessage(message, raw_message.source, allocator);
    // Process the message and return the response if there is one to send.
    switch (message_result) {
        .ok => {},
        .discard => {},
        .response => |response| {
            var stream = std.io.fixedBufferStream(buffer);
            try response.write(stream.writer());
            try utils.sendTo(fd, stream.getWritten(), raw_message.source);
        },
    }
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Initialize the Server with short-term authenitcation.
    var server = ztun.Server.init(gpa.allocator(), ztun.Server.Options{ .authentication_type = .none });
    defer server.deinit();

    // Register user "anon" with password "password".
    try server.registerUser("anon", .{ .short_term = .{ .password = "password" } });

    // Create and bind IPv6 dual-stack socket to localhost.
    const socket = try createAndBindSocket();

    // Allocate the buffer used to receive the requests.
    var buffer = try gpa.allocator().alloc(u8, 4096);
    defer gpa.allocator().free(buffer);

    // Allocate the buffer that will be used as temporary memory for the answer.
    var arena_storage = try gpa.allocator().alloc(u8, 4096);
    defer gpa.allocator().free(arena_storage);
    var arena_state = std.heap.FixedBufferAllocator.init(arena_storage);

    // Set up the file descriptors for poll.
    var fds = [_]linux.pollfd{
        .{ .fd = socket, .events = linux.POLL.IN, .revents = 0 },
    };

    // Loop indefinitely
    while (true) {
        // Reset all previous allocations in one shot.
        arena_state.reset();

        // Wait for event
        const result = linux.poll(&fds, fds.len, -1);
        if (linux.getErrno(result) != linux.E.SUCCESS) {
            return error.UnexpectedFailure;
        }

        for (&fds) |*entry| {
            if (entry.revents & linux.POLL.IN > 0) {
                handleMessage(entry.fd, &server, buffer, arena_state.allocator()) catch |err| {
                    std.log.err("Unexpected error: {}", .{err});
                    continue;
                };
            }
        }
    }
}
