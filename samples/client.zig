// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("ztun");
const utils = @import("utils.zig");

const linux = std.os.linux;

pub fn makeRequest(allocator: std.mem.Allocator, use_authentication: bool) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    // Binding request with random transaction ID.
    message_builder.setClass(ztun.Class.request);
    message_builder.setMethod(ztun.Method.binding);
    message_builder.randomTransactionId();

    if (use_authentication) {
        // Authentication attributes.
        const username_attribute = ztun.attr.common.Username{ .value = "anon" };
        const attribute = try username_attribute.toAttribute(allocator);
        errdefer allocator.free(attribute.data);
        try message_builder.addAttribute(attribute);

        const authentication = ztun.auth.Authentication{ .short_term = ztun.auth.ShortTermAuthentication{ .password = "password" } };

        message_builder.addMessageIntegrity(authentication);
        message_builder.addMessageIntegritySha256(authentication);
    }

    // Add a fingerprint for validity check.
    message_builder.addFingerprint();
    return try message_builder.build();
}

pub fn main() anyerror!void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();

    // Parse options from command line.
    const options = try utils.Options.fromArgsAlloc(arena_state.allocator());

    // Create socket.
    var socket = try utils.createSocket(utils.SocketType.fromAddress(options.address));

    // Allocate buffer to serialize the request and deserialize the answer.
    var buffer = try arena_state.allocator().alloc(u8, 4096);
    defer arena_state.allocator().free(buffer);

    // Build a request
    const request_message = try makeRequest(arena_state.allocator(), true);
    defer request_message.deinit(arena_state.allocator());

    // Serialize the request.
    const raw_request_message = blk: {
        var stream = std.io.fixedBufferStream(buffer);
        try request_message.write(stream.writer());
        break :blk stream.getWritten();
    };

    // Send the request to the remote server.
    try utils.sendTo(socket, raw_request_message, options.address);

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
