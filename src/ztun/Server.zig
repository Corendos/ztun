// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const Self = @This();

const attr = @import("attributes.zig");
const ztun = @import("../ztun.zig");

const software_version_attribute = attr.common.Software{ .value = std.fmt.comptimePrint("ztun v{}", .{@import("constants.zig").version}) };

/// Options to configure the STUN server.
pub const Options = struct {
    /// Type of authentication to use.
    authentication_type: ztun.auth.AuthenticationType = .none,
};

/// Server related error.
pub const Error = error{
    MethodNotAllowedForClass,
    InvalidFingerprint,
    UnknownTransaction,
} || ztun.MessageBuilder.Error || std.mem.Allocator.Error;

/// Stores the options of the server.
options: Options,
/// Allocator used by the server internally.
allocator: std.mem.Allocator,
/// Stores the registered users.
user_map: std.StringHashMap(ztun.auth.Authentication),

/// Initializes a server using the given allocator and options.
pub fn init(allocator: std.mem.Allocator, options: Options) Self {
    return Self{
        .options = options,
        .allocator = allocator,
        .user_map = std.StringHashMap(ztun.auth.Authentication).init(allocator),
    };
}

/// Deinitializes the server.
pub fn deinit(self: *Self) void {
    var user_iterator = self.user_map.iterator();
    while (user_iterator.next()) |entry| switch (entry.value_ptr.*) {
        .none => {},
        .short_term => |value| {
            self.allocator.free(value.password);
        },
        .long_term => |value| {
            self.allocator.free(value.username);
            self.allocator.free(value.password);
            self.allocator.free(value.realm);
        },
    };
    self.user_map.deinit();
}

/// Returns true if the given attribute is not known by the server.
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

/// Returns the list of unknown attributes or null if they are all known.
fn lookForUnknownAttributes(message: ztun.Message, allocator: std.mem.Allocator) error{OutOfMemory}!?[]u16 {
    var comprehension_required_unknown_attributes = try std.ArrayList(u16).initCapacity(allocator, message.attributes.len);
    defer comprehension_required_unknown_attributes.deinit();

    for (message.attributes) |a| if (isUnknownAttribute(a.type) and attr.isComprehensionRequired(a.type)) {
        comprehension_required_unknown_attributes.appendAssumeCapacity(a.type);
    };

    return if (comprehension_required_unknown_attributes.items.len == 0) null else try comprehension_required_unknown_attributes.toOwnedSlice();
}

/// Returns a STUN message representing a Bad Request response_error.
fn makeBadRequestMessage(request: ztun.Message, allocator: std.mem.Allocator) ztun.MessageBuilder.Error!ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    message_builder.setHeader(request.type.method, .error_response, request.transaction_id);

    const error_code_attribute = try (attr.common.ErrorCode{ .value = .bad_request, .reason = "Bad Request" }).toAttribute(allocator);
    try message_builder.addAttribute(error_code_attribute);

    const software_attribute = try software_version_attribute.toAttribute(allocator);
    errdefer allocator.free(software_attribute.data);
    try message_builder.addAttribute(software_attribute);

    return try message_builder.build();
}

/// Returns a STUN message representing a Unauthenticated response_error.
fn makeUnauthenticatedMessage(request: ztun.Message, reason: []const u8, allocator: std.mem.Allocator) ztun.MessageBuilder.Error!ztun.Message {
    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();

    message_builder.setHeader(request.type.method, .error_response, request.transaction_id);

    const error_code_attribute = try (attr.common.ErrorCode{ .value = .unauthenticated, .reason = reason }).toAttribute(allocator);
    try message_builder.addAttribute(error_code_attribute);

    const software_attribute = try software_version_attribute.toAttribute(allocator);
    errdefer allocator.free(software_attribute.data);
    try message_builder.addAttribute(software_attribute);

    return try message_builder.build();
}

/// Returns a STUN message representing a Unknown Attributes response_error.
fn makeUnknownAttributesMessage(request: ztun.Message, unknown_attributes: []u16, allocator: std.mem.Allocator) ztun.MessageBuilder.Error!ztun.Message {
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

/// Type of Authentication result.
const AuthenticationResultType = enum {
    discard,
    authentication,
    response,
};

/// Represents the result of an authentication to the server.
const AuthenticationResult = union(AuthenticationResultType) {
    /// The message should be discarded silently,
    discard: void,
    /// The authentication succeeded and the result contains the parameters.
    authentication: ztun.auth.Authentication,
    /// The authentication failed and produced a response to send back.
    response: ztun.Message,
};

/// Represents some details about the message integrity attributes of a message.
const MessageIntegrityDetails = struct {
    /// Stores the index of the USERNAME attribute if any.
    username_index: ?usize = null,
    /// Stores the index of the MESSAGE-INTEGRITY attribute if any.
    simple_index: ?usize = null,
    /// Stores the index of the MESSAGE-INTEGRITY-SHA256 if any
    sha256_index: ?usize = null,

    /// Returns true if the message contains the required attribute for authentication.
    pub inline fn isValid(self: MessageIntegrityDetails) bool {
        return (self.simple_index != null or self.sha256_index != null) and self.username_index != null;
    }

    /// Extracts details from a list of attribute.
    pub fn fromAttributes(attributes: []const ztun.Attribute) MessageIntegrityDetails {
        var details = MessageIntegrityDetails{};
        for (attributes, 0..) |attribute, i| {
            switch (attribute.type) {
                @as(u16, ztun.attr.Type.message_integrity) => details.simple_index = i,
                @as(u16, ztun.attr.Type.message_integrity_sha256) => details.sha256_index = i,
                @as(u16, ztun.attr.Type.username) => details.username_index = i,
                else => {},
            }
        }
        return details;
    }
};

pub const AuthenticationError = error{
    InvalidMessageIntegrityDetails,
    InvalidAuthentication,
} || std.mem.Allocator.Error;

/// Returns the credentials of a given user or null if there is none.
fn authenticateUser(self: Self, username: []const u8) ?ztun.auth.Authentication {
    const authentication = self.user_map.get(username) orelse return null;
    return authentication;
}

/// Authenticates the sender of a STUN message using the short-term mechanism.
fn authenticateShortTerm(message: ztun.Message, message_integrity_type: ztun.MessageIntegrityType, message_integrity_attribute_index: usize, key: []const u8, allocator: std.mem.Allocator) AuthenticationError!bool {
    std.debug.assert(message.type.class == .request);

    return message.checkMessageIntegrity(message_integrity_type, message_integrity_attribute_index, key, allocator) catch return false;
}

/// Authenticates the sender of a STUN message using the long-term mechanism.
fn authenticateLongTerm(message: ztun.Message, message_integrity_type: ztun.MessageIntegrityType, message_integrity_attribute_index: usize, key: []const u8, allocator: std.mem.Allocator) AuthenticationError!bool {
    _ = message_integrity_attribute_index;
    _ = message_integrity_type;
    _ = key;
    _ = allocator;
    _ = message;
    @panic("Long-Term authentication is not implemented.");
}

/// Authenticates the sender of a STUN message using the server configuration.
fn authenticate(self: Self, message: ztun.Message, message_integrity_details: MessageIntegrityDetails, allocator: std.mem.Allocator) AuthenticationError!ztun.auth.Authentication {
    if (self.options.authentication_type == .none) return .{ .none = .{} };

    if (!message_integrity_details.isValid()) {
        return error.InvalidMessageIntegrityDetails;
    }
    const message_integrity_type: ztun.MessageIntegrityType = if (message_integrity_details.sha256_index != null) .sha256 else .classic;
    const message_integrity_attribute_index = message_integrity_details.sha256_index orelse message_integrity_details.simple_index orelse unreachable;

    const authentication = self.authenticateUser(message.attributes[message_integrity_details.username_index.?].data) orelse return error.InvalidAuthentication;
    const key = authentication.computeKeyAlloc(allocator) catch return error.InvalidAuthentication;
    defer allocator.free(key);

    const success = switch (self.options.authentication_type) {
        .short_term => try authenticateShortTerm(message, message_integrity_type, message_integrity_attribute_index, key, allocator),
        .long_term => try authenticateLongTerm(message, message_integrity_type, message_integrity_attribute_index, key, allocator),
        .none => unreachable,
    };

    if (!success) return error.InvalidAuthentication;

    return authentication;
}

/// Handles a request after the basic checks and authentication (if needed) has been done.
pub fn handleRequest(server: Self, message: ztun.Message, source: std.net.Address, authentication: ztun.auth.Authentication, message_integrity_details: MessageIntegrityDetails, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) Error!MessageResult {
    _ = server;
    std.log.debug("Received {s} request from {any}", .{ @tagName(message.type.method), source });

    const unknown_attributes_opt = try lookForUnknownAttributes(message, temporary_arena);
    if (unknown_attributes_opt) |unknown_attributes| {
        defer temporary_arena.free(unknown_attributes);
        return .{ .response = try makeUnknownAttributesMessage(message, unknown_attributes, allocator) };
    }

    var message_builder = ztun.MessageBuilder.init(allocator);
    defer message_builder.deinit();
    message_builder.setHeader(message.type.method, .error_response, message.transaction_id);
    message_builder.setClass(.success_response);

    const xor_mapped_address_attribute = switch (source.any.family) {
        std.os.AF.INET => blk: {
            const ipv4 = source.in;
            const xor_mapped_address_attribute = attr.common.encode(attr.common.MappedAddress{
                .port = ipv4.sa.port,
                .family = attr.common.AddressFamily{ .ipv4 = ipv4.sa.addr },
            }, message.transaction_id);
            break :blk try xor_mapped_address_attribute.toAttribute(allocator);
        },
        std.os.AF.INET6 => blk: {
            const ipv6 = source.in6;
            const xor_mapped_address_attribute = attr.common.encode(attr.common.MappedAddress{
                .port = ipv6.sa.port,
                .family = attr.common.AddressFamily{ .ipv6 = std.mem.bytesAsValue(u128, ipv6.sa.addr[0..]).* },
            }, message.transaction_id);
            break :blk try xor_mapped_address_attribute.toAttribute(allocator);
        },
        else => return MessageResult{ .response = try makeBadRequestMessage(message, allocator) },
    };
    errdefer allocator.free(xor_mapped_address_attribute.data);
    try message_builder.addAttribute(xor_mapped_address_attribute);

    const software_attribute = try software_version_attribute.toAttribute(allocator);
    errdefer allocator.free(software_attribute.data);
    try message_builder.addAttribute(software_attribute);

    if (authentication != .none) {
        if (message_integrity_details.sha256_index != null) {
            message_builder.addMessageIntegritySha256(authentication);
        } else if (message_integrity_details.simple_index != null) {
            message_builder.addMessageIntegrity(authentication);
        } else unreachable;
    }

    message_builder.addFingerprint();
    return .{ .response = try message_builder.build() };
}

/// Handles an indication after the basic checks and authentication (if needed) has been done.
pub fn handleIndication(server: Self, message: ztun.Message, authentication: ztun.auth.Authentication, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) Error!MessageResult {
    _ = authentication;
    _ = temporary_arena;
    _ = message;
    _ = allocator;
    _ = server;
    @panic("Indication handling is not implemented");
}

/// Handles a response after the basic checks and authentication (if needed) has been done.
pub fn handleResponse(server: Self, message: ztun.Message, success: bool, authentication: ztun.auth.Authentication, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) Error!MessageResult {
    _ = authentication;
    _ = temporary_arena;
    _ = message;
    _ = server;
    _ = allocator;
    _ = success;
    @panic("Response handling is not implemented");
}

/// Represents the type of result that can be returned by the server when handling a message.
pub const MessageResultType = enum {
    discard,
    ok,
    response,
};

/// Represents the result returned by the server when handling a message.
pub const MessageResult = union(MessageResultType) {
    /// The message should be discarded.
    discard: void,
    /// The message has been handled correctly, but doesn't require any response to be send back.
    ok: void,
    /// The message has been handled correctly and this contains the response to send back.
    response: ztun.Message,
};

/// Handles a message sent to the server and returns a `MessageResult` result or an error in case of critical failure.
pub fn handleMessage(self: Self, message: ztun.Message, source: std.net.Address, allocator: std.mem.Allocator) !MessageResult {
    var temp_arena_state = std.heap.ArenaAllocator.init(self.allocator);
    defer temp_arena_state.deinit();

    // NOTE(Corendos): If the message has been successfully decoded, some basic checks already have been done.

    // Check that the method is allowed for the given class. If not, discard message as described in Section 6.3.
    if (!ztun.isMethodAllowedForClass(message.type.method, message.type.class)) return .{ .discard = {} };

    // Check the fingerprint if it's present
    if (!message.checkFingerprint(temp_arena_state.allocator())) return .{ .discard = {} };

    const message_integrity_details = MessageIntegrityDetails.fromAttributes(message.attributes);

    // Check authentication
    const authentication = self.authenticate(message, message_integrity_details, temp_arena_state.allocator()) catch |err| switch (err) {
        error.InvalidMessageIntegrityDetails, error.InvalidAuthentication => return .{ .response = try makeUnauthenticatedMessage(message, "Unauthenticated", allocator) },
        error.OutOfMemory => return .{ .discard = {} },
    };

    // Handle the message depending on its type.
    return switch (message.type.class) {
        .request => try self.handleRequest(message, source, authentication, message_integrity_details, temp_arena_state.allocator(), allocator),
        .indication => try self.handleIndication(message, authentication, temp_arena_state.allocator(), allocator),
        .success_response => try self.handleResponse(message, true, authentication, temp_arena_state.allocator(), allocator),
        .error_response => try self.handleResponse(message, false, authentication, temp_arena_state.allocator(), allocator),
    };
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
    try std.testing.expectEqual(MessageResultType.discard, try server.handleMessage(wrong_message, undefined, std.testing.allocator));
}

pub fn registerUser(self: *Self, username: []const u8, authentication: ztun.auth.Authentication) !void {
    if (authentication == .none) return;

    const gop = try self.user_map.getOrPut(username);
    if (gop.found_existing) switch (gop.value_ptr.*) {
        .none => {},
        .short_term => |value| {
            self.allocator.free(value.password);
        },
        .long_term => |value| {
            self.allocator.free(value.username);
            self.allocator.free(value.password);
            self.allocator.free(value.realm);
        },
    };
    gop.value_ptr.* = switch (authentication) {
        .none => @unionInit(ztun.auth.Authentication, "none", .{}),
        .short_term => |value| @unionInit(ztun.auth.Authentication, "short_term", .{
            .password = try self.allocator.dupe(u8, value.password),
        }),
        .long_term => |value| @unionInit(ztun.auth.Authentication, "long_term", .{
            .username = try self.allocator.dupe(u8, value.username),
            .password = try self.allocator.dupe(u8, value.password),
            .realm = try self.allocator.dupe(u8, value.realm),
        }),
    };
}
