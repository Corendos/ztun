// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("ztun");
const utils = @import("utils.zig");

const linux = std.os.linux;

pub fn createAndBindSockets() ![2]i32 {
    const ipv4_bind_address = ztun.net.Address{ .ipv4 = try ztun.net.Ipv4Address.parse("127.0.0.1", 8888) };
    const ipv6_bind_address = ztun.net.Address{ .ipv6 = try ztun.net.Ipv6Address.parse("::1", 8888) };

    var ipv4_socket = try utils.createSocket(.ipv4);
    try utils.bindSocket(ipv4_socket, ipv4_bind_address);

    var ipv6_socket = try utils.createSocket(.ipv6);
    try utils.bindSocket(ipv6_socket, ipv6_bind_address);

    return .{ ipv4_socket, ipv6_socket };
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Initialize the Server with short-term authenitcation.
    var server = ztun.Server.init(gpa.allocator(), ztun.Server.Options{ .authentication_type = .short_term });
    defer server.deinit();

    // Create and bind sockets (IPv4 and IPv6) to localhost.
    const sockets = try createAndBindSockets();

    // Allocate the buffer used to receive the requests.
    var receive_buffer = try gpa.allocator().alloc(u8, 4096);
    defer gpa.allocator().free(receive_buffer);

    // Allocate the buffer that will be used as temporary memory for the answer.
    var arena_storage = try gpa.allocator().alloc(u8, 4096);
    defer gpa.allocator().free(arena_storage);
    var arena_state = std.heap.FixedBufferAllocator.init(arena_storage);

    // Set up the file descriptors for poll.
    var fds = [_]linux.pollfd{
        .{ .fd = sockets[0], .events = linux.POLL.IN, .revents = 0 },
        .{ .fd = sockets[1], .events = linux.POLL.IN, .revents = 0 },
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

        for (fds) |*entry| {
            if (entry.revents & linux.POLL.IN > 0) {
                // Receive the message in the previously allocated buffer.
                const message = utils.receiveFrom(entry.fd, receive_buffer) catch |err| {
                    std.log.err("{}", .{err});
                    continue;
                };

                // Process the message and return the response if there is one to send.
                if (server.processRawMessage(message.data, message.source, arena_state.allocator())) |response| {
                    try utils.sendTo(entry.fd, response, message.source);
                    arena_state.allocator().free(response);
                }
            }
        }
    }
}
