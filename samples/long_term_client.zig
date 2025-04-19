// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("ztun");
const utils = @import("utils/utils.zig");

const linux = std.os.linux;

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

    // Make the initial request.
    const initial_request = b: {
        var message_builder = ztun.MessageBuilder.init(allocator);
        defer message_builder.deinit();

        // Binding request with random transaction ID.
        message_builder.setClass(ztun.Class.request);
        message_builder.setMethod(ztun.Method.binding);
        message_builder.randomTransactionId();

        // Add a fingerprint for validity check.
        message_builder.addFingerprint();
        break :b try message_builder.build();
    };
    defer initial_request.deinit(allocator);

    const raw_initial_request = b: {
        var stream = std.io.fixedBufferStream(buffer);
        const writer = stream.writer();
        try initial_request.write(writer);
        break :b stream.getWritten();
    };

    // Send the initial request
    _ = try utils.sendTo(socket, raw_initial_request, options.address);

    // Receive the initial response
    var source: std.net.Address = undefined;
    const raw_initial_response = try utils.receiveFrom(socket, buffer, &source);
    const initial_response: ztun.Message = blk: {
        var stream = std.io.fixedBufferStream(raw_initial_response);
        break :blk try ztun.Message.readAlloc(allocator, stream.reader());
    };
    defer initial_response.deinit(allocator);

    // Print a human-readable description of the initial response.
    std.log.info("{}", .{ztun.fmt.messageFormatter(initial_response)});

    // Retrieve the Nonce from the initial response.
    const nonce_value = for (initial_response.attributes) |a| {
        if (a.type == ztun.attr.Type.nonce) {
            const nonce_attribute = try ztun.attr.common.Nonce.fromAttribute(a);
            break nonce_attribute.value;
        }
    } else return error.MissingNonceInResponse;

    // Make the subsequent request.
    const subsequent_request = b: {
        var message_builder = ztun.MessageBuilder.init(allocator);
        defer message_builder.deinit();

        // Binding request with random transaction ID.
        message_builder.setClass(ztun.Class.request);
        message_builder.setMethod(ztun.Method.binding);
        message_builder.randomTransactionId();

        // Add the USERNAME attribute.
        const username_attribute = try (ztun.attr.common.Username{ .value = "corendos" }).toAttribute(allocator);
        errdefer allocator.free(username_attribute.data);
        try message_builder.addAttribute(username_attribute);

        // Add the REALM attribute.
        const realm_attribute = try (ztun.attr.common.Realm{ .value = "default" }).toAttribute(allocator);
        errdefer allocator.free(realm_attribute.data);
        try message_builder.addAttribute(realm_attribute);

        // Add the NONCE attribute.
        const nonce_attribute = try (ztun.attr.common.Nonce{ .value = nonce_value }).toAttribute(allocator);
        errdefer allocator.free(nonce_attribute.data);
        try message_builder.addAttribute(nonce_attribute);

        // Add the MESSAGE-INTEGRITY attribute from long-term authentication parameters.
        const authentication_parameters = ztun.auth.LongTermAuthenticationParameters{ .username = "corendos", .realm = "default", .password = "password" };
        const key = try authentication_parameters.computeKeyAlloc(allocator, ztun.auth.Algorithm.default(ztun.auth.AlgorithmType.md5));
        defer allocator.free(key);
        message_builder.addMessageIntegrity(key);

        // Add a fingerprint for validity check.
        message_builder.addFingerprint();
        break :b try message_builder.build();
    };
    defer subsequent_request.deinit(allocator);

    const raw_subsequent_request = b: {
        var stream = std.io.fixedBufferStream(buffer);
        const writer = stream.writer();
        try subsequent_request.write(writer);
        break :b stream.getWritten();
    };

    // Send the subsequent request
    _ = try utils.sendTo(socket, raw_subsequent_request, options.address);

    // Receive the subsequent response
    const raw_subsequent_response = try utils.receiveFrom(socket, buffer, &source);
    const subsequent_response: ztun.Message = blk: {
        var stream = std.io.fixedBufferStream(raw_subsequent_response);
        break :blk try ztun.Message.readAlloc(allocator, stream.reader());
    };
    defer subsequent_response.deinit(allocator);

    // Print a human-readable description of the subsequent response.
    std.log.info("{}", .{ztun.fmt.messageFormatter(subsequent_response)});
}
