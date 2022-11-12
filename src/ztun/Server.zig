// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const Self = @This();

const attr = @import("attributes.zig");
const net = @import("net.zig");

const Method = @import("lib.zig").Method;
const Class = @import("lib.zig").Class;
const Message = @import("lib.zig").Message;
const MessageBuilder = @import("lib.zig").MessageBuilder;

const version_attribute = attr.Attribute{
    .software = attr.SoftwareAttribute{ .value = std.fmt.comptimePrint("v{}", .{@import("constants.zig").version}) },
};

const AgentContext = struct {};

pub const Error = error{
    MethodNotAllowedForClass,
    InvalidFingerprint,
    UnknownTransaction,
    UnexpectedError,
    Discard,
};

allocator: std.mem.Allocator,
agent_map: std.AutoHashMap(u96, AgentContext),

pub fn init(allocator: std.mem.Allocator) Self {
    return Self{
        .allocator = allocator,
        .agent_map = std.AutoHashMap(u96, AgentContext).init(allocator),
    };
}

pub fn deinit(self: *Self) void {
    self.agent_map.deinit();
}

fn isMethodAllowedForClass(method: Method, class: Class) bool {
    return switch (class) {
        .request => method == .binding,
        .indication => method == .binding,
        .success_response => method == .binding,
        .error_response => method == .binding,
    };
}

pub fn processMessage(server: Self, allocator: std.mem.Allocator, message: Message, source: net.Address) Error!?Message {
    if (!isMethodAllowedForClass(message.@"type".method, message.@"type".class)) return error.MethodNotAllowedForClass;

    var has_fingerprint: bool = false;
    for (message.attributes) |a, i| {
        if (a == .known and a.known == .fingerprint) {
            has_fingerprint = true;
            if (i != message.attributes.len - 1) return error.InvalidFingerprint;
        }
    }

    if (has_fingerprint) {}

    switch (message.@"type".class) {
        .error_response, .success_response => {
            if (server.agent_map.get(message.transaction_id) == null) return error.UnknownTransaction;
        },
        else => {},
    }

    // TODO(Corentin): Fingerprint check if required.

    // TODO(Corentin): Other authentication handling if required.

    var response: ?Message = null;
    switch (message.@"type".class) {
        .request => {
            response = try server.handleRequest(allocator, message, source);
        },
        .indication => try server.handleIndication(allocator, message),
        .success_response => try server.handleResponse(allocator, message, true),
        .error_response => try server.handleResponse(allocator, message, false),
    }

    return response;
}

pub fn handleRequest(server: Self, allocator: std.mem.Allocator, message: Message, source: net.Address) Error!Message {
    std.log.info("Received {s} request from {any}", .{ @tagName(message.type.method), source });
    _ = server;
    var comprehension_required_unknown_attributes = std.ArrayList(u16).initCapacity(allocator, message.attributes.len) catch return error.UnexpectedError;
    defer comprehension_required_unknown_attributes.deinit();
    for (message.attributes) |a| switch (a) {
        .raw => |raw_attribute| {
            if (attr.isComprehensionRequiredAttribute(raw_attribute.value)) {
                comprehension_required_unknown_attributes.appendAssumeCapacity(raw_attribute.value);
            }
        },
        else => {},
    };
    var message_builder = MessageBuilder.init(allocator);
    defer message_builder.deinit();
    message_builder.setMethod(message.@"type".method);
    message_builder.transactionId(message.transaction_id);

    if (comprehension_required_unknown_attributes.items.len > 0) {
        message_builder.setClass(.error_response);
        const error_code_attribute = attr.Attribute{
            .error_code = attr.ErrorCodeAttribute{
                .value = .unknown_attribute,
                .reason = "Unknown comprehension-required attributes",
            },
        };
        message_builder.addKnownAttribute(error_code_attribute) catch return error.UnexpectedError;
        const unknown_attributes = attr.Attribute{
            .unknown_attributes = attr.UnknownAttribute{ .attribute_types = comprehension_required_unknown_attributes.toOwnedSlice() },
        };
        message_builder.addKnownAttribute(unknown_attributes) catch return error.UnexpectedError;
        message_builder.addKnownAttribute(version_attribute) catch return error.UnexpectedError;
        return message_builder.build() catch return error.UnexpectedError;
    }

    message_builder.setClass(.success_response);
    const xor_mapped_address_attribute = attr.Attribute{
        .xor_mapped_address = attr.XorMappedAddressAttribute.encode(
            .{
                .port = source.ipv4.port,
                .family = attr.Family{ .ipv4 = source.ipv4.value },
            },
            message.transaction_id,
        ),
    };
    message_builder.addKnownAttribute(xor_mapped_address_attribute) catch return error.UnexpectedError;
    message_builder.addKnownAttribute(version_attribute) catch return error.UnexpectedError;
    return message_builder.build() catch return error.UnexpectedError;
}

pub fn handleIndication(server: Self, allocator: std.mem.Allocator, message: Message) Error!void {
    _ = message;
    _ = allocator;
    _ = server;
}

pub fn handleResponse(server: Self, allocator: std.mem.Allocator, message: Message, success: bool) Error!void {
    _ = message;
    _ = allocator;
    _ = success;
    _ = server;
}

pub fn processRawMessage(self: Self, allocator: std.mem.Allocator, bytes: []const u8, source: net.Address) ?[]const u8 {
    var input_stream = std.io.fixedBufferStream(bytes);
    const message = Message.deserialize(input_stream.reader(), allocator) catch |err| {
        std.log.err("{any}", .{err});
        return null;
    };

    const response_opt = self.processMessage(allocator, message, source) catch |err| {
        std.log.err("{any}", .{err});
        return null;
    };
    if (response_opt) |response| {
        var output_buffer = allocator.alloc(u8, 2048) catch |err| {
            std.log.err("{any}", .{err});
            return null;
        };
        errdefer allocator.free(output_buffer);

        var output_stream = std.io.fixedBufferStream(output_buffer);
        response.serialize(output_stream.writer()) catch |err| {
            std.log.err("{any}", .{err});
            return null;
        };
        return output_stream.getWritten();
    }
    return null;
}
