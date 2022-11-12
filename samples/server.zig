// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("ztun");

const linux = std.os.linux;

pub fn createSocket() !i32 {
    var result = linux.socket(linux.PF.INET, linux.SOCK.DGRAM, 0);
    if (linux.getErrno(result) != linux.E.SUCCESS) {
        return error.SocketCreationFailed;
    }
    return @truncate(i32, @intCast(isize, result));
}

pub fn bindSocket(socket: i32, address: ztun.net.Address) !void {
    if (address == .ipv6) @panic("Not implemented");
    var raw_address = std.net.Address{
        .in = std.net.Ip4Address.init(@bitCast([4]u8, address.ipv4.value), address.ipv4.port),
    };
    var result = linux.bind(socket, &raw_address.any, raw_address.getOsSockLen());
    if (linux.getErrno(result) != linux.E.SUCCESS) {
        std.log.err("{}", .{linux.getErrno(result)});
        return error.SocketBindFailed;
    }
}

pub fn sendTo(socket: i32, bytes: []const u8, address: ztun.net.Address) !void {
    if (address == .ipv6) @panic("Not implemented");
    var raw_address = std.net.Address{
        .in = std.net.Ip4Address.init(@bitCast([4]u8, address.ipv4.value), address.ipv4.port),
    };
    const result = linux.sendto(socket, bytes.ptr, bytes.len, 0, &raw_address.any, raw_address.getOsSockLen());
    if (linux.getErrno(result) != linux.E.SUCCESS) {
        std.log.err("{}", .{linux.getErrno(result)});
        return error.SendFailed;
    }
}

const Message = struct {
    data: []const u8,
    source: ztun.net.Address,
};

pub fn receiveFrom(socket: i32, buf: []u8) !Message {
    var raw_address_length: linux.socklen_t = @sizeOf(linux.sockaddr);
    var raw_address: std.net.Address = undefined;

    const result = linux.recvfrom(socket, buf.ptr, buf.len, 0, &raw_address.any, &raw_address_length);
    if (linux.getErrno(result) != linux.E.SUCCESS) return error.ReceiveFailed;

    const address = ztun.net.Address{
        .ipv4 = ztun.net.Ipv4Address{
            .value = raw_address.in.sa.addr,
            .port = raw_address.in.getPort(),
        },
    };

    return Message{
        .data = buf[0..result],
        .source = address,
    };
}

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const bind_address = ztun.net.Address{ .ipv4 = try ztun.net.Ipv4Address.parse("127.0.0.1", 8888) };

    var server = ztun.Server.init(gpa.allocator());
    defer server.deinit();

    var socket = try createSocket();
    try bindSocket(socket, bind_address);

    var buffer = try gpa.allocator().alloc(u8, 4096);
    defer gpa.allocator().free(buffer);

    var scratch_buffer = try gpa.allocator().alloc(u8, 8192);
    defer gpa.allocator().free(scratch_buffer);

    var arena_state = std.heap.FixedBufferAllocator.init(scratch_buffer);

    while (true) {
        arena_state.reset();
        const message = receiveFrom(socket, buffer) catch |err| {
            std.log.err("{}", .{err});
            continue;
        };

        if (server.processRawMessage(arena_state.allocator(), message.data, message.source)) |response| {
            try sendTo(socket, response, message.source);
            arena_state.allocator().free(response);
        }
    }
}
