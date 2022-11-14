// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const Self = @This();

const attr = @import("attributes.zig");
const net = @import("net.zig");
const ztun = @import("lib.zig");

const version_attribute = ztun.Attribute{
    .software = attr.Software{ .value = std.fmt.comptimePrint("v{}", .{@import("constants.zig").version}) },
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

fn isMethodAllowedForClass(method: ztun.Method, class: ztun.Class) bool {
    return switch (class) {
        .request => method == .binding,
        .indication => method == .binding,
        .success_response => method == .binding,
        .error_response => method == .binding,
    };
}

pub fn processMessage(server: Self, allocator: std.mem.Allocator, message: ztun.Message, source: net.Address) Error!?ztun.Message {
    if (!isMethodAllowedForClass(message.@"type".method, message.@"type".class)) return error.MethodNotAllowedForClass;

    var fingerprint_opt: ?u32 = null;
    for (message.attributes) |a, i| {
        if (a == .known and a.known == .fingerprint) {
            fingerprint_opt = a.known.fingerprint.value;
            if (i != message.attributes.len - 1) return error.InvalidFingerprint;
        }
    }

    if (fingerprint_opt) |fingerprint| {
        const fingerprint_message = ztun.Message.fromParts(message.type.class, message.type.method, message.transaction_id, message.attributes[0 .. message.attributes.len - 1]);
        const computed_fingerprint = fingerprint_message.computeFingerprint(allocator) catch return error.UnexpectedError;
        if (computed_fingerprint != fingerprint) return error.InvalidFingerprint;
    }

    switch (message.@"type".class) {
        .error_response, .success_response => {
            if (server.agent_map.get(message.transaction_id) == null) return error.UnknownTransaction;
        },
        else => {},
    }

    // TODO(Corentin): Fingerprint check if required.

    // TODO(Corentin): Other authentication handling if required.

    var response: ?ztun.Message = null;
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

pub fn handleRequest(server: Self, allocator: std.mem.Allocator, message: ztun.Message, source: net.Address) Error!ztun.Message {
    std.log.info("Received {s} request from {any}", .{ @tagName(message.type.method), source });
    _ = server;
    var comprehension_required_unknown_attributes = std.ArrayList(u16).initCapacity(allocator, message.attributes.len) catch return error.UnexpectedError;
    defer comprehension_required_unknown_attributes.deinit();
    for (message.attributes) |a| switch (a) {
        .raw => |raw_attribute| {
            if (attr.isComprehensionRequiredRaw(raw_attribute.value)) {
                comprehension_required_unknown_attributes.appendAssumeCapacity(raw_attribute.value);
            }
        },
        else => {},
    };
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();
    message_builder.setMethod(message.@"type".method);
    message_builder.transactionId(message.transaction_id);

    if (comprehension_required_unknown_attributes.items.len > 0) {
        message_builder.setClass(.error_response);
        const error_code_attribute = ztun.Attribute{
            .error_code = attr.ErrorCode{
                .value = .unknown_attribute,
                .reason = "Unknown comprehension-required attributes",
            },
        };
        message_builder.addAttribute(error_code_attribute) catch return error.UnexpectedError;
        const unknown_attributes = ztun.Attribute{
            .unknown_attributes = attr.UnknownAttributes{ .attribute_types = comprehension_required_unknown_attributes.toOwnedSlice() },
        };
        message_builder.addAttribute(unknown_attributes) catch return error.UnexpectedError;
        message_builder.addAttribute(version_attribute) catch return error.UnexpectedError;
        return message_builder.build() catch return error.UnexpectedError;
    }

    message_builder.setClass(.success_response);
    const xor_mapped_address_attribute = switch (source) {
        .ipv4 => ztun.Attribute{
            .xor_mapped_address = attr.XorMappedAddress.encode(
                .{
                    .port = source.ipv4.port,
                    .family = attr.AddressFamily{ .ipv4 = source.ipv4.value },
                },
                message.transaction_id,
            ),
        },
        .ipv6 => ztun.Attribute{
            .xor_mapped_address = attr.XorMappedAddress.encode(
                .{
                    .port = source.ipv6.port,
                    .family = attr.AddressFamily{ .ipv6 = source.ipv6.value },
                },
                message.transaction_id,
            ),
        },
    };
    message_builder.addAttribute(xor_mapped_address_attribute) catch return error.UnexpectedError;
    message_builder.addAttribute(version_attribute) catch return error.UnexpectedError;
    message_builder.addFingerprint();
    return message_builder.build() catch return error.UnexpectedError;
}

pub fn handleIndication(server: Self, allocator: std.mem.Allocator, message: ztun.Message) Error!void {
    _ = message;
    _ = allocator;
    _ = server;
}

pub fn handleResponse(server: Self, allocator: std.mem.Allocator, message: ztun.Message, success: bool) Error!void {
    _ = message;
    _ = allocator;
    _ = success;
    _ = server;
}

pub fn processRawMessage(self: Self, allocator: std.mem.Allocator, bytes: []const u8, source: net.Address) ?[]const u8 {
    var input_stream = std.io.fixedBufferStream(bytes);
    const message = ztun.Message.deserialize(input_stream.reader(), allocator) catch |err| {
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

test "check fingerprint while processing a message" {
    const message = msg: {
        var builder = ztun.MessageBuilder.init(std.testing.allocator);
        defer builder.deinit();

        builder.setClass(.request);
        builder.setMethod(.binding);
        builder.transactionId(0x0102030405060708090A0B);
        builder.addFingerprint();
        break :msg try builder.build();
    };
    defer message.deinit(std.testing.allocator);
    const true_fingerprint = message.attributes[0].known.fingerprint.value;

    var server = Self.init(std.testing.allocator);
    defer server.deinit();

    const wrong_message = ztun.Message{
        .type = message.type,
        .transaction_id = message.transaction_id,
        .length = message.length,
        .attributes = &.{ztun.GenericAttribute{
            .known = ztun.Attribute{
                .fingerprint = attr.Fingerprint{
                    .value = true_fingerprint + 1,
                },
            },
        }},
    };
    try std.testing.expectError(error.InvalidFingerprint, server.processMessage(std.testing.allocator, wrong_message, undefined));
}
