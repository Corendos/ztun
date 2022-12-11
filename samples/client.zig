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

pub fn socketTypeFromAddress(address: ztun.net.Address) utils.SocketType {
    return switch (address) {
        .ipv4 => .ipv4,
        .ipv6 => .ipv6,
    };
}

pub fn main() anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();

    // Parse options from command line.
    const options = try Options.fromArgsAlloc(arena_state.allocator());

    // Create socket.
    var socket = try utils.createSocket(socketTypeFromAddress(options.server_address));

    // Allocate buffer to serialize the request and deserialize the answer.
    var buffer = try arena_state.allocator().alloc(u8, 4096);
    defer arena_state.allocator().free(buffer);

    // Build a request
    const request_message = msg: {
        var message_builder = ztun.MessageBuilder.init(arena_state.allocator());
        defer message_builder.deinit();

        // Binding request with random transaction ID.
        message_builder.setClass(ztun.Class.request);
        message_builder.setMethod(ztun.Method.binding);
        message_builder.randomTransactionId();

        // Authentication attributes.
        const username_attribute = ztun.attr.common.Username{ .value = "anon" };
        const attribute = try username_attribute.toAttribute(arena_state.allocator());
        errdefer arena_state.allocator().free(attribute.data);
        try message_builder.addAttribute(attribute);

        const authentication = ztun.auth.Authentication{ .short_term = ztun.auth.ShortTermAuthentication{ .password = "password" } };

        message_builder.addMessageIntegrity(authentication);
        message_builder.addMessageIntegritySha256(authentication);

        // Add a fingerprint for validity check.
        message_builder.addFingerprint();
        break :msg try message_builder.build();
    };
    defer request_message.deinit(arena_state.allocator());

    // Serialize the request.
    const raw_request_message = blk: {
        var stream = std.io.fixedBufferStream(buffer);
        try request_message.write(stream.writer());
        break :blk stream.getWritten();
    };

    // Send the request to the remote server.
    try utils.sendTo(socket, raw_request_message, options.server_address);

    // Receive the response
    const raw_message = try utils.receive(socket, buffer);
    const message: ztun.Message = blk: {
        var stream = std.io.fixedBufferStream(raw_message);
        break :blk try ztun.Message.readAlloc(stream.reader(), arena_state.allocator());
    };
    defer message.deinit(arena_state.allocator());

    // Print a human-readable description of the response.
    std.log.info("{}", .{ztun.fmt.messageFormatter(message)});
}
