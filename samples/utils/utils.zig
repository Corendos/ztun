// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const Options = struct {
    address: std.Io.net.IpAddress,

    pub fn fromArgsAlloc(allocator: std.mem.Allocator, args: std.process.Args) !Options {
        var options: Options = undefined;

        var arg_iterator = try args.iterateAllocator(allocator);
        defer arg_iterator.deinit();

        _ = arg_iterator.skip();

        const raw_address = arg_iterator.next() orelse return error.MissingArgument;
        const raw_port = arg_iterator.next() orelse return error.MissingArgument;

        if (std.mem.indexOf(u8, raw_address, ":")) |_| {
            // Probably IPv6
            options.address = try std.Io.net.IpAddress.parseIp6(raw_address, try std.fmt.parseUnsigned(u16, raw_port, 10));
        } else {
            // Probably IPv4
            options.address = try std.Io.net.IpAddress.parseIp4(raw_address, try std.fmt.parseUnsigned(u16, raw_port, 10));
        }

        return options;
    }
};
