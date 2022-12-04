// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const Self = @This();

const attr = @import("attributes.zig");
const net = @import("net.zig");
const ztun = @import("../ztun.zig");

const software_version_attribute = attr.common.Software{ .value = std.fmt.comptimePrint("ztun v{}", .{@import("constants.zig").version}) };

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

fn isUnknownAttribute(value: u16) bool {
    return switch (value) {
        @as(u16, attr.Type.mapped_address) => false,
        @as(u16, attr.Type.xor_mapped_address) => false,
        @as(u16, attr.Type.username) => false,
        @as(u16, attr.Type.userhash) => false,
        @as(u16, attr.Type.message_integrity) => false,
        @as(u16, attr.Type.message_integrity_sha256) => false,
        @as(u16, attr.Type.fingerprint) => false,
        @as(u16, attr.Type.error_code) => false,
        @as(u16, attr.Type.realm) => false,
        @as(u16, attr.Type.nonce) => false,
        @as(u16, attr.Type.password_algorithms) => false,
        @as(u16, attr.Type.password_algorithm) => false,
        @as(u16, attr.Type.unknown_attributes) => false,
        @as(u16, attr.Type.software) => false,
        @as(u16, attr.Type.alternate_server) => false,
        @as(u16, attr.Type.alternate_domain) => false,
        else => true,
    };
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
        if (a.type == @as(u16, attr.Type.fingerprint)) {
            const fingerprint_attribute = attr.common.Fingerprint.fromAttribute(a) catch return error.UnexpectedError;
            fingerprint_opt = fingerprint_attribute.value;
            if (i != message.attributes.len - 1) return error.InvalidFingerprint;
        }
    }

    if (fingerprint_opt) |fingerprint| {
        const fingerprint_message = ztun.Message.fromParts(message.type.class, message.type.method, message.transaction_id, message.attributes[0 .. message.attributes.len - 1]);
        const computed_fingerprint = fingerprint_message.computeFingerprint(allocator) catch return error.UnexpectedError;
        if (computed_fingerprint != fingerprint) return error.InvalidFingerprint;
    }
}

pub fn processMessage(server: Self, message: ztun.Message, source: net.Address, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) Error!?ztun.Message {
    std.log.debug("Basic checks", .{});
    try doBasicMessageCheck(message, temporary_arena);

    var response: ?ztun.Message = null;
    switch (message.type.class) {
        .request => {
            response = try server.handleRequest(message, source, temporary_arena, allocator);
        },
        .indication => try server.handleIndication(message, temporary_arena, allocator),
        .success_response => try server.handleResponse(message, true, temporary_arena, allocator),
        .error_response => try server.handleResponse(message, false, temporary_arena, allocator),
    }

    return response;
}

fn lookForUnknownAttributes(message: ztun.Message, allocator: std.mem.Allocator) error{OutOfMemory}!?[]u16 {
    var comprehension_required_unknown_attributes = try std.ArrayList(u16).initCapacity(allocator, message.attributes.len);
    defer comprehension_required_unknown_attributes.deinit();

    for (message.attributes) |a| if (isUnknownAttribute(a.type) and attr.isComprehensionRequired(a.type)) {
        comprehension_required_unknown_attributes.appendAssumeCapacity(a.type);
    };

    return if (comprehension_required_unknown_attributes.items.len == 0) null else comprehension_required_unknown_attributes.toOwnedSlice();
}

const MessageIntegrityDetails = struct {
    attribute_index: ?usize = null,
    attribute_index_sha256: ?usize = null,
    username_attribute: ?attr.common.Username = null,

    pub inline fn isValid(self: MessageIntegrityDetails) bool {
        return (self.attribute_index != null or self.attribute_index_sha256 != null) and self.username_attribute != null;
    }
};

fn getMessageIntegrityDetails(message: ztun.Message) !MessageIntegrityDetails {
    var details = MessageIntegrityDetails{};

    for (message.attributes) |a, i| switch (a.type) {
        @as(u16, attr.Type.message_integrity) => details.attribute_index = i,
        @as(u16, attr.Type.message_integrity_sha256) => details.attribute_index_sha256 = i,
        @as(u16, attr.Type.username) => details.username_attribute = try attr.common.Username.fromAttribute(a),
        else => {},
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

fn checkMessageIntegrity(details: MessageIntegrityDetails, authentication_details: AuthenticationDetails, message: ztun.Message, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) !?ztun.Message {
    var storage: [32]u8 = undefined;

    const key = authentication_details.authentication.computeKeyAlloc(temporary_arena) catch return error.UnexpectedError;
    defer key.deinit(temporary_arena);

    if (details.attribute_index_sha256) |index| {
        const computed_message_integrity = try ztun.Message.fromParts(message.type.class, message.type.method, message.transaction_id, message.attributes[0..index])
            .computeMessageIntegritySha256(temporary_arena, &storage, key.value);
        const message_integrity_sha256_attribute = try attr.common.MessageIntegritySha256.fromAttribute(message.attributes[index]);
        const length = message_integrity_sha256_attribute.length;
        const message_integrity = message_integrity_sha256_attribute.storage[0..length];

        if (!std.mem.eql(u8, message_integrity, computed_message_integrity)) return try makeUnauthenticatedMessage(message, "Invalid Message Integrity SHA256", allocator);
    } else if (details.attribute_index) |index| {
        const computed_message_integrity = try ztun.Message.fromParts(message.type.class, message.type.method, message.transaction_id, message.attributes[0..index])
            .computeMessageIntegrity(temporary_arena, storage[0..20], key.value);
        const message_integrity_attribute = try attr.common.MessageIntegrity.fromAttribute(message.attributes[index]);
        const message_integrity = message_integrity_attribute.value[0..20];

        if (!std.mem.eql(u8, message_integrity, computed_message_integrity)) return try makeUnauthenticatedMessage(message, "Invalid Message Integrity", allocator);
    } else unreachable;

    return null;
}

fn makeBadRequestMessage(request: ztun.Message, allocator: std.mem.Allocator) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    message_builder.setHeader(request.type.method, .error_response, request.transaction_id);

    const error_code_attribute = try (attr.common.ErrorCode{ .value = .unknown_attribute, .reason = "Bad Request" }).toAttribute(allocator);
    try message_builder.addAttribute(error_code_attribute);

    const software_attribute = try software_version_attribute.toAttribute(allocator);
    errdefer allocator.free(software_attribute.data);
    try message_builder.addAttribute(software_attribute);

    return try message_builder.build();
}

fn makeUnauthenticatedMessage(request: ztun.Message, reason: []const u8, allocator: std.mem.Allocator) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    message_builder.setHeader(request.type.method, .error_response, request.transaction_id);

    const error_code_attribute = try (attr.common.ErrorCode{ .value = .unknown_attribute, .reason = reason }).toAttribute(allocator);
    try message_builder.addAttribute(error_code_attribute);

    const software_attribute = try software_version_attribute.toAttribute(allocator);
    errdefer allocator.free(software_attribute.data);
    try message_builder.addAttribute(software_attribute);

    return try message_builder.build();
}

fn makeUnknownAttributesMessage(request: ztun.Message, unknown_attributes: []u16, allocator: std.mem.Allocator) !ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    message_builder.setHeader(request.type.method, .error_response, request.transaction_id);

    const error_code_attribute = try (attr.common.ErrorCode{ .value = .unknown_attribute, .reason = "Unknown comprehension-required attributes" }).toAttribute(allocator);
    errdefer allocator.free(error_code_attribute.data);
    try message_builder.addAttribute(error_code_attribute);

    const unknown_attributes_attribute = try (attr.common.UnknownAttributes{ .attribute_types = unknown_attributes }).toAttribute(allocator);
    errdefer allocator.free(unknown_attributes_attribute.data);
    try message_builder.addAttribute(unknown_attributes_attribute);

    const software_attribute = try software_version_attribute.toAttribute(allocator);
    errdefer allocator.free(software_attribute.data);
    try message_builder.addAttribute(software_attribute);

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

fn checkAuthentication(server: Self, message: ztun.Message, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) Error!AuthenticationResult {
    var authentication_details = AuthenticationDetails{ .authentication = undefined };
    if (server.options.authentication_type == .none) return AuthenticationResult{ .success = authentication_details };

    // First check of Section 9.1.3
    std.log.debug("Getting message integrity details", .{});
    const message_integrity_details = getMessageIntegrityDetails(message) catch return error.UnexpectedError;
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

    std.log.debug("Check message Integrity", .{});
    // Third check of Section 9.1.3
    if (checkMessageIntegrity(message_integrity_details, authentication_details, message, temporary_arena, allocator) catch return error.UnexpectedError) |response| {
        return AuthenticationResult{ .failure = response };
    }

    return AuthenticationResult{ .success = authentication_details };
}

pub fn handleRequest(server: Self, message: ztun.Message, source: net.Address, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) Error!ztun.Message {
    std.log.debug("Received {s} request from {any}", .{ @tagName(message.type.method), source });

    // Check Message integrity and return potential error response.
    const authentication_details: AuthenticationDetails = switch (try server.checkAuthentication(message, temporary_arena, allocator)) {
        .failure => |response| return response,
        .success => |details| details,
    };

    const unknown_attributes_opt = lookForUnknownAttributes(message, temporary_arena) catch return error.UnexpectedError;
    if (unknown_attributes_opt) |unknown_attributes| {
        defer temporary_arena.free(unknown_attributes);
        return makeUnknownAttributesMessage(message, unknown_attributes, allocator) catch return error.UnexpectedError;
    }

    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();
    message_builder.setHeader(message.type.method, .error_response, message.transaction_id);
    message_builder.setClass(.success_response);

    const xor_mapped_address_attribute = switch (source) {
        .ipv4 => |ipv4| blk: {
            const xor_mapped_address_attribute = attr.common.encode(attr.common.MappedAddress{
                .port = ipv4.port,
                .family = attr.common.AddressFamily{ .ipv4 = ipv4.value },
            }, message.transaction_id);
            break :blk xor_mapped_address_attribute.toAttribute(allocator) catch return error.UnexpectedError;
        },

        .ipv6 => |ipv6| blk: {
            const xor_mapped_address_attribute = attr.common.encode(attr.common.MappedAddress{
                .port = ipv6.port,
                .family = attr.common.AddressFamily{ .ipv6 = ipv6.value },
            }, message.transaction_id);
            break :blk xor_mapped_address_attribute.toAttribute(allocator) catch return error.UnexpectedError;
        },
    };
    errdefer allocator.free(xor_mapped_address_attribute.data);
    message_builder.addAttribute(xor_mapped_address_attribute) catch return error.UnexpectedError;

    const software_attribute = software_version_attribute.toAttribute(allocator) catch return error.UnexpectedError;
    errdefer allocator.free(software_attribute.data);
    message_builder.addAttribute(software_attribute) catch return error.UnexpectedError;

    if (authentication_details.has_message_integrity_sha256) {
        message_builder.addMessageIntegritySha256(authentication_details.authentication);
    } else if (authentication_details.has_message_integrity) {
        message_builder.addMessageIntegrity(authentication_details.authentication);
    }

    message_builder.addFingerprint();
    return message_builder.build() catch return error.UnexpectedError;
}

pub fn handleIndication(server: Self, message: ztun.Message, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) Error!void {
    _ = temporary_arena;
    _ = message;
    _ = allocator;
    _ = server;
}

pub fn handleResponse(server: Self, message: ztun.Message, success: bool, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) Error!void {
    _ = temporary_arena;
    _ = message;
    _ = server;
    _ = allocator;
    _ = success;
}

pub const SafeStringFormatter = struct {
    source: []const u8,

    pub fn format(self: SafeStringFormatter, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = options;
        _ = fmt;
        for (self.source) |c| {
            if (std.ascii.isPrint(c)) {
                try writer.writeByte(c);
            } else {
                try writer.print("\\x{x:0>2}", .{c});
            }
        }
    }
};

pub fn safeStringFormatter(source: []const u8) SafeStringFormatter {
    return SafeStringFormatter{ .source = source };
}

pub fn processRawMessage(self: Self, bytes: []const u8, source: net.Address, allocator: std.mem.Allocator) ?[]const u8 {
    var arena_storage = self.allocator.alloc(u8, 4096) catch |err| {
        std.log.err("{any}", .{err});
        return null;
    };
    defer self.allocator.free(arena_storage);

    var arena_state = std.heap.FixedBufferAllocator.init(arena_storage);

    var input_stream = std.io.fixedBufferStream(bytes);
    std.log.debug("Reading message", .{});
    const message = ztun.Message.readAlloc(input_stream.reader(), arena_state.allocator()) catch |err| {
        std.log.err("{any}", .{err});
        return null;
    };
    defer message.deinit(arena_state.allocator());

    std.log.debug("Processing message", .{});
    const response_opt = self.processMessage(message, source, arena_state.allocator(), allocator) catch |err| {
        std.log.err("{any}", .{err});
        return null;
    };
    if (response_opt) |response| {
        defer response.deinit(allocator);
        var output_buffer = allocator.alloc(u8, response.length + ztun.constants.message_header_length) catch |err| {
            std.log.err("{any}", .{err});
            return null;
        };
        errdefer allocator.free(output_buffer);

        var output_stream = std.io.fixedBufferStream(output_buffer);
        response.write(output_stream.writer()) catch |err| {
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
    const true_fingerprint_attribute = try attr.common.Fingerprint.fromAttribute(message.attributes[0]);

    var server = Self.init(std.testing.allocator, .{});
    defer server.deinit();

    const wrong_fingerprint_attribute = try (attr.common.Fingerprint{ .value = true_fingerprint_attribute.value + 1 }).toAttribute(std.testing.allocator);
    std.testing.allocator.free(wrong_fingerprint_attribute.data);

    const wrong_message = ztun.Message{
        .type = message.type,
        .transaction_id = message.transaction_id,
        .length = message.length,
        .attributes = &.{wrong_fingerprint_attribute},
    };
    try std.testing.expectError(error.InvalidFingerprint, server.processMessage(wrong_message, undefined, std.testing.allocator, std.testing.allocator));
}
