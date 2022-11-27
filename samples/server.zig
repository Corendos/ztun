// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("ztun");
const utils = @import("utils.zig");

const linux = std.os.linux;

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const ipv4_bind_address = ztun.net.Address{ .ipv4 = try ztun.net.Ipv4Address.parse("127.0.0.1", 8888) };
    const ipv6_bind_address = ztun.net.Address{ .ipv6 = try ztun.net.Ipv6Address.parse("::1", 8888) };

    var server = ztun.Server.init(gpa.allocator(), ztun.Server.Options{ .authentication_type = .none });
    defer server.deinit();

    var ipv4_socket = try utils.createSocket(.ipv4);
    try utils.bindSocket(ipv4_socket, ipv4_bind_address);

    var ipv6_socket = try utils.createSocket(.ipv6);
    try utils.bindSocket(ipv6_socket, ipv6_bind_address);

    var buffer = try gpa.allocator().alloc(u8, 4096);
    defer gpa.allocator().free(buffer);

    var scratch_buffer = try gpa.allocator().alloc(u8, 8192);
    defer gpa.allocator().free(scratch_buffer);

    var arena_state = std.heap.FixedBufferAllocator.init(scratch_buffer);

    var fds = [_]linux.pollfd{
        .{ .fd = ipv4_socket, .events = linux.POLL.IN, .revents = 0 },
        .{ .fd = ipv6_socket, .events = linux.POLL.IN, .revents = 0 },
    };

    while (true) {
        arena_state.reset();

        const result = linux.poll(&fds, fds.len, -1);
        if (linux.getErrno(result) != linux.E.SUCCESS) {
            return error.UnexpectedFailure;
        }

        for (fds) |*entry| {
            if (entry.revents & linux.POLL.IN > 0) {
                const message = utils.receiveFrom(entry.fd, buffer) catch |err| {
                    std.log.err("{}", .{err});
                    continue;
                };

                if (server.processRawMessage(message.data, message.source, arena_state.allocator())) |response| {
                    try utils.sendTo(entry.fd, response, message.source);
                    arena_state.allocator().free(response);
                }
            }
        }
    }
}
