// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const ztun = @import("ztun");

const utils = @import("utils/utils.zig");

pub fn handleMessage(io: std.Io, allocator: std.mem.Allocator, socket: std.Io.net.Socket, server: *ztun.Server, buffer: []u8) !void {
    const raw_message = try socket.receive(io, buffer);

    const message = blk: {
        var reader = std.Io.Reader.fixed(raw_message.data);
        break :blk try ztun.Message.readAlloc(allocator, &reader);
    };
    defer message.deinit(allocator);

    const message_result = try server.handleMessage(io, allocator, message, raw_message.from);
    // Process the message and return the response if there is one to send.
    switch (message_result) {
        .ok => {},
        .discard => {},
        .response => |response| {
            var writer = std.Io.Writer.fixed(buffer);
            try response.write(&writer);
            try socket.send(io, &raw_message.from, writer.buffered());
            response.deinit(allocator);
        },
    }
}

pub fn main(init: std.process.Init) anyerror!void {
    const allocator = init.gpa;
    const io = init.io;

    // Parse options from command line.
    const options = try utils.Options.fromArgsAlloc(allocator, init.minimal.args);

    // Create and bind socket.
    const socket = try options.address.bind(io, .{ .mode = .dgram });
    defer socket.close(io);

    // Initialize the Server with Long-Term authentication.
    var server = ztun.Server.init(allocator, ztun.Server.Options{ .authentication_type = .long_term, .realm = "default" });
    defer server.deinit();

    // Add a Long-Term user
    try server.registerLongTermUser("corendos", "password");

    // Allocate the buffer used to receive the requests.
    const buffer = try allocator.alloc(u8, 4096);
    defer allocator.free(buffer);

    // Indefinitely wait for messages.
    while (true) {
        handleMessage(io, allocator, socket, &server, buffer) catch |err| {
            std.log.err("Unexpected error: {}", .{err});
            continue;
        };
    }
}
