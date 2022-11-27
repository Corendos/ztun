// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const Self = @This();

const attr = @import("attributes.zig");
const net = @import("net.zig");
const ztun = @import("lib.zig");

const version_attribute = ztun.Attribute{
    .software = attr.Software{ .value = std.fmt.comptimePrint("ztun v{}", .{@import("constants.zig").version}) },
};

pub const AuthenticationType = enum {
    none,
    short_term,
    long_term,
};

pub const Options = struct {
    authentication_type: AuthenticationType = .none,
};

pub const Error = error{
    MethodNotAllowedForClass,
    InvalidFingerprint,
    UnknownTransaction,
    UnexpectedError,
    Discard,
};

options: Options,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, options: Options) Self {
    return Self{
        .options = options,
        .allocator = allocator,
    };
}

pub fn deinit(self: *Self) void {
    _ = self;
}

fn isMethodAllowedForClass(method: ztun.Method, class: ztun.Class) bool {
    return switch (class) {
        .request => method == .binding,
        .indication => method == .binding,
        .success_response => method == .binding,
        .error_response => method == .binding,
    };
}

fn doBasicMessageCheck(message: ztun.Message, allocator: std.mem.Allocator) Error!void {
    if (!isMethodAllowedForClass(message.type.method, message.type.class)) return error.MethodNotAllowedForClass;

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
}

pub fn processMessage(server: Self, message: ztun.Message, source: net.Address, allocator: std.mem.Allocator) Error!?ztun.Message {
    try doBasicMessageCheck(message, allocator);

    var response: ?ztun.Message = null;
    switch (message.type.class) {
        .request => {
            response = try server.handleRequest(message, source, allocator);
        },
        .indication => try server.handleIndication(message, allocator),
        .success_response => try server.handleResponse(message, true, allocator),
        .error_response => try server.handleResponse(message, false, allocator),
    }

    return response;
}

fn lookForUnknownAttributes(message: ztun.Message, allocator: std.mem.Allocator) error{OutOfMemory}!?[]u16 {
    var comprehension_required_unknown_attributes = try std.ArrayList(u16).initCapacity(allocator, message.attributes.len);
    defer comprehension_required_unknown_attributes.deinit();

    for (message.attributes) |a| switch (a) {
        .raw => |raw_attribute| {
            if (attr.isComprehensionRequiredRaw(raw_attribute.value)) {
                comprehension_required_unknown_attributes.appendAssumeCapacity(raw_attribute.value);
            }
        },
        else => {},
    };

    return if (comprehension_required_unknown_attributes.items.len == 0) null else comprehension_required_unknown_attributes.toOwnedSlice();
}

const MessageIntegrityDetails = struct {
    attribute_index: ?usize = null,
    attribute_index_sha256: ?usize = null,
    username_attribute: ?attr.Username = null,

    pub inline fn isValid(self: MessageIntegrityDetails) bool {
        return (self.attribute_index != null or self.attribute_index_sha256 != null) and self.username_attribute != null;
    }
};

fn getMessageIntegrityDetails(message: ztun.Message) MessageIntegrityDetails {
    var details = MessageIntegrityDetails{};

    for (message.attributes) |a, i| if (a == .known) {
        switch (a.known) {
            .message_integrity => details.attribute_index = i,
            .message_integrity_sha256 => details.attribute_index_sha256 = i,
            .username => |ua| details.username_attribute = ua,
            else => {},
        }
    };

    return details;
}

fn authenticateUser(server: Self, username: []const u8) ?ztun.auth.Authentication {
    if (!std.mem.eql(u8, username, "anon")) return null;
    // TODO(Corentin): implement checking
    const password = "password";
    return switch (server.options.authentication_type) {
        .short_term => ztun.auth.Authentication{ .short_term = ztun.auth.ShortTermAuthentication{ .password = password } },
        .long_term => ztun.auth.Authentication{ .long_term = ztun.auth.LongTermAuthentication{ .username = username, .password = password, .realm = "realm" } },
        else => unreachable,
    };
}

fn checkMessageIntegrity(details: MessageIntegrityDetails, message: ztun.Message, key: []const u8, allocator: std.mem.Allocator) !?ztun.Message {
    var storage: [32]u8 = undefined;

    if (details.attribute_index_sha256) |index| {
        const computed_message_integrity = try ztun.Message.fromParts(message.type.class, message.type.method, message.transaction_id, message.attributes[0..index])
            .computeMessageIntegritySha256(allocator, &storage, key);
        const message_integrity = message.attributes[index].known.message_integrity_sha256.storage[0..];

        if (!std.mem.eql(u8, message_integrity, computed_message_integrity)) return try makeUnauthenticatedMessage(message, "Invalid Message Integrity SHA256", allocator);
    } else if (details.attribute_index) |index| {
        const computed_message_integrity = try ztun.Message.fromParts(message.type.class, message.type.method, message.transaction_id, message.attributes[0..index])
            .computeMessageIntegrity(allocator, storage[0..20], key);
        const message_integrity = message.attributes[index].known.message_integrity.value[0..];

        if (!std.mem.eql(u8, message_integrity, computed_message_integrity)) return try makeUnauthenticatedMessage(message, "Invalid Message Integrity", allocator);
    } else unreachable;

    return null;
}

fn makeBadRequestMessage(request: ztun.Message, allocator: std.mem.Allocator) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    message_builder.setHeader(request.type.method, .error_response, request.transaction_id);
    try message_builder.addAttribute(.{ .error_code = .{ .value = .bad_request, .reason = "Bad Request" } });
    try message_builder.addAttribute(version_attribute);

    return try message_builder.build();
}

fn makeUnauthenticatedMessage(request: ztun.Message, reason: []const u8, allocator: std.mem.Allocator) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    message_builder.setHeader(request.type.method, .error_response, request.transaction_id);
    try message_builder.addAttribute(.{ .error_code = .{ .value = .unauthenticated, .reason = reason } });
    try message_builder.addAttribute(version_attribute);

    return try message_builder.build();
}

fn makeUnknownAttributesMessage(request: ztun.Message, unknown_attributes: []u16, allocator: std.mem.Allocator) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    message_builder.setHeader(request.type.method, .error_response, request.transaction_id);
    try message_builder.addAttribute(.{ .error_code = .{ .value = .unknown_attribute, .reason = "Unknown comprehension-required attributes" } });
    const unknown_attributes_attribute = .{ .unknown_attributes = .{ .attribute_types = unknown_attributes } };
    try message_builder.addAttribute(unknown_attributes_attribute);
    try message_builder.addAttribute(version_attribute);

    return try message_builder.build();
}

const AuthenticationDetails = struct {
    authentication: ztun.auth.Authentication,
    has_message_integrity_sha256: bool = false,
    has_message_integrity: bool = false,
};

const AuthenticationResult = union(enum) {
    failure: ztun.Message,
    success: AuthenticationDetails,
};

fn checkAuthentication(server: Self, message: ztun.Message, allocator: std.mem.Allocator) Error!AuthenticationResult {
    var authentication_details = AuthenticationDetails{ .authentication = undefined };
    if (server.options.authentication_type == .none) return AuthenticationResult{ .success = authentication_details };

    // First check of Section 9.1.3
    std.log.debug("Getting message integrity details", .{});
    const message_integrity_details = getMessageIntegrityDetails(message);
    if (!message_integrity_details.isValid()) {
        const response = makeBadRequestMessage(message, allocator) catch return error.UnexpectedError;
        return AuthenticationResult{ .failure = response };
    } else {
        authentication_details.has_message_integrity_sha256 = message_integrity_details.attribute_index_sha256 != null;
        authentication_details.has_message_integrity = message_integrity_details.attribute_index != null;
    }

    std.log.debug("Authenticate user", .{});
    // Second check of Section 9.1.3
    authentication_details.authentication = server.authenticateUser(message_integrity_details.username_attribute.?.value) orelse {
        const response = makeUnauthenticatedMessage(message, "Invalid username", allocator) catch return error.UnexpectedError;
        return AuthenticationResult{ .failure = response };
    };
    const key = authentication_details.authentication.computeKeyAlloc(allocator) catch return error.UnexpectedError;
    defer allocator.free(key);

    // Third check of Section 9.1.3
    if (checkMessageIntegrity(message_integrity_details, message, key, allocator) catch return error.UnexpectedError) |response| {
        return AuthenticationResult{ .failure = response };
    }

    return AuthenticationResult{ .success = authentication_details };
}

pub fn handleRequest(server: Self, message: ztun.Message, source: net.Address, allocator: std.mem.Allocator) Error!ztun.Message {
    std.log.debug("Received {s} request from {any}", .{ @tagName(message.type.method), source });

    // Check Message integrity and return potential error response.
    const authentication_details: AuthenticationDetails = switch (try server.checkAuthentication(message, allocator)) {
        .failure => |response| return response,
        .success => |details| details,
    };

    const unknown_attributes_opt = lookForUnknownAttributes(message, allocator) catch return error.UnexpectedError;
    if (unknown_attributes_opt) |unknown_attributes| {
        errdefer allocator.free(unknown_attributes);
        return makeUnknownAttributesMessage(message, unknown_attributes, allocator) catch return error.UnexpectedError;
    }

    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();
    message_builder.setHeader(message.type.method, .error_response, message.transaction_id);
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

    if (authentication_details.has_message_integrity_sha256) {
        message_builder.addMessageIntegritySha256(authentication_details.authentication);
    } else if (authentication_details.has_message_integrity) {
        message_builder.addMessageIntegrity(authentication_details.authentication);
    }

    message_builder.addFingerprint();
    return message_builder.build() catch return error.UnexpectedError;
}

pub fn handleIndication(server: Self, message: ztun.Message, allocator: std.mem.Allocator) Error!void {
    _ = message;
    _ = allocator;
    _ = server;
}

pub fn handleResponse(server: Self, message: ztun.Message, success: bool, allocator: std.mem.Allocator) Error!void {
    _ = message;
    _ = server;
    _ = allocator;
    _ = success;
}

pub fn processRawMessage(self: Self, bytes: []const u8, source: net.Address, allocator: std.mem.Allocator) ?[]const u8 {
    var input_stream = std.io.fixedBufferStream(bytes);
    const message = ztun.Message.deserialize(input_stream.reader(), allocator) catch |err| {
        std.log.err("{any}", .{err});
        return null;
    };

    const response_opt = self.processMessage(message, source, allocator) catch |err| {
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

    var server = Self.init(std.testing.allocator, .{});
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
    try std.testing.expectError(error.InvalidFingerprint, server.processMessage(wrong_message, undefined, std.testing.allocator));
}
