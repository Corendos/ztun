// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const Options = struct {
    address: std.net.Address,

    pub fn fromArgsAlloc(allocator: std.mem.Allocator) !Options {
        var options: Options = undefined;

        var arg_iterator = try std.process.argsWithAllocator(allocator);
        defer arg_iterator.deinit();

        _ = arg_iterator.skip();

        const raw_address = arg_iterator.next() orelse return error.MissingArgument;
        const raw_port = arg_iterator.next() orelse return error.MissingArgument;

        if (std.mem.indexOf(u8, raw_address, ":")) |_| {
            // Probably IPv6
            options.address = try std.net.Address.parseIp6(raw_address, try std.fmt.parseUnsigned(u16, raw_port, 10));
        } else {
            // Probably IPv4
            options.address = try std.net.Address.parseIp4(raw_address, try std.fmt.parseUnsigned(u16, raw_port, 10));
        }

        return options;
    }
};

pub fn receiveFrom(socket: std.posix.socket_t, buf: []u8, address: *std.net.Address) ![]const u8 {
    var storage: std.posix.sockaddr.storage = undefined;
    var raw_address_length: std.posix.socklen_t = @sizeOf(@TypeOf(storage));
    const raw_address = @as(*align(4) std.posix.sockaddr, @ptrCast(&storage));

    const result = try std.posix.recvfrom(socket, buf, 0, raw_address, &raw_address_length);
    address.* = std.net.Address.initPosix(raw_address);
    return buf[0..result];
}

pub fn sendTo(socket: std.posix.socket_t, buf: []const u8, address: std.net.Address) !usize {
    return std.posix.sendto(socket, buf, 0, &address.any, address.getOsSockLen());
}
