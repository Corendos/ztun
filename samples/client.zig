// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("ztun");
const utils = @import("utils.zig");

const linux = std.os.linux;

const Options = struct {
    server_address: ztun.net.Address,

    pub fn fromArgsAlloc(allocator: std.mem.Allocator) !Options {
        var options: Options = undefined;

        var arg_iterator = try std.process.argsWithAllocator(allocator);
        defer arg_iterator.deinit();

        _ = arg_iterator.skip();

        const raw_address = arg_iterator.next() orelse return error.MissingArgument;
        const raw_port = arg_iterator.next() orelse return error.MissingArgument;

        if (std.mem.indexOf(u8, raw_address, ":")) |_| {
            // Probably IPv6
            options.server_address = ztun.net.Address{
                .ipv6 = try ztun.net.Ipv6Address.parse(raw_address, try std.fmt.parseUnsigned(u16, raw_port, 10)),
            };
        } else {
            // Probably IPv4
            options.server_address = ztun.net.Address{
                .ipv4 = try ztun.net.Ipv4Address.parse(raw_address, try std.fmt.parseUnsigned(u16, raw_port, 10)),
            };
        }

        return options;
    }
};

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const options = try Options.fromArgsAlloc(gpa.allocator());

    var socket = try utils.createSocket(.ipv6);

    var buffer = try gpa.allocator().alloc(u8, 4096);
    defer gpa.allocator().free(buffer);

    var scratch_buffer = try gpa.allocator().alloc(u8, 8192);
    defer gpa.allocator().free(scratch_buffer);

    var scratch_allocator_state = std.heap.FixedBufferAllocator.init(scratch_buffer);

    const request_message = msg: {
        var message_builder = ztun.MessageBuilder.init(scratch_allocator_state.allocator());
        defer scratch_allocator_state.reset();
        message_builder.setClass(ztun.Class.request);
        message_builder.setMethod(ztun.Method.binding);
        message_builder.randomTransactionId();
        break :msg try message_builder.build();
    };

    const raw_request_message = blk: {
        var stream = std.io.fixedBufferStream(buffer);
        try request_message.serialize(stream.writer());
        break :blk stream.getWritten();
    };

    try utils.sendTo(socket, raw_request_message, options.server_address);
    const raw_message = try utils.receive(socket, buffer);
    const message: ztun.Message = blk: {
        var stream = std.io.fixedBufferStream(raw_message);
        break :blk try ztun.Message.deserialize(stream.reader(), scratch_allocator_state.allocator());
    };

    std.log.debug("{any}", .{message});
}
