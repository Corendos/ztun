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

    // Make the request.
    const request = b: {
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
    defer request.deinit(allocator);

    const raw_request = b: {
        var stream = std.io.fixedBufferStream(buffer);
        const writer = stream.writer();
        try request.write(writer);
        break :b stream.getWritten();
    };

    // Send the request
    _ = try utils.sendTo(socket, raw_request, options.address);

    // Receive the response
    var source: std.net.Address = undefined;
    const raw_message = try utils.receiveFrom(socket, buffer, &source);
    const message: ztun.Message = blk: {
        var stream = std.io.fixedBufferStream(raw_message);
        break :blk try ztun.Message.readAlloc(allocator, stream.reader());
    };
    defer message.deinit(allocator);

    // Print a human-readable description of the response.
    std.log.info("{}", .{ztun.fmt.messageFormatter(message)});
}
