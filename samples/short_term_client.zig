// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const linux = std.os.linux;

const ztun = @import("ztun");

const utils = @import("utils/utils.zig");

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    // Parse options from command line.
    const options = try utils.Options.fromArgsAlloc(allocator);

    // Create socket.
    const socket = try std.posix.socket(options.address.any.family, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(socket);

    // Allocate the buffer that will be used to send/receive the request/response.
    const buffer = try allocator.alloc(u8, 4096);
    defer allocator.free(buffer);

    // Make the request.
    const request = b: {
        var message_builder = ztun.MessageBuilder.init(allocator);
        defer message_builder.deinit();

        // Binding request with random transaction ID.
        message_builder.setClass(ztun.Class.request);
        message_builder.setMethod(ztun.Method.binding);
        message_builder.randomTransactionId();

        // Adding the USERNAME attribute.
        const username_attribute = try (ztun.attr.common.Username{ .value = "corendos" }).toAttribute(allocator);
        errdefer allocator.free(username_attribute.data);
        try message_builder.addAttribute(username_attribute);

        // Adding the MESSAGE-INTEGRITY attribute from authentication parameters.
        const authentication_parameters = ztun.auth.ShortTermAuthenticationParameters{ .password = "password" };
        const key = try authentication_parameters.computeKeyAlloc(allocator);
        defer allocator.free(key);
        message_builder.addMessageIntegrity(key);

        // Add a fingerprint for validity check.
        message_builder.addFingerprint();
        break :b try message_builder.build();
    };
    defer request.deinit(allocator);

    const raw_request = b: {
        var writer = std.Io.Writer.fixed(buffer);
        try request.write(&writer);
        break :b writer.buffered();
    };

    // Send the request
    _ = try utils.sendTo(socket, raw_request, options.address);

    // Receive the response
    var source: std.net.Address = undefined;
    const raw_message = try utils.receiveFrom(socket, buffer, &source);
    const message: ztun.Message = blk: {
        var reader = std.Io.Reader.fixed(raw_message);
        break :blk try ztun.Message.readAlloc(allocator, &reader);
    };
    defer message.deinit(allocator);

    // Print a human-readable description of the response.
    std.log.info("{f}", .{message});
}
