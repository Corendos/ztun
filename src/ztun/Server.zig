// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const Self = @This();

const attr = @import("attributes.zig");
const net = @import("net.zig");
const ztun = @import("../ztun.zig");

const software_version_attribute = attr.common.Software{ .value = std.fmt.comptimePrint("ztun v{}", .{@import("constants.zig").version}) };

/// Authentication used by the server.
pub const AuthenticationType = enum {
    /// No authentication.
    none,
    /// Short-term authentication.
    short_term,
    /// Long-term authentication.
    long_term,
};

/// Options to configure the STUN server.
pub const Options = struct {
    /// Type of authentication to use.
    authentication_type: AuthenticationType = .none,
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

/// Initializes a server using the given allocator and options.
pub fn init(allocator: std.mem.Allocator, options: Options) Self {
    return Self{
        .options = options,
        .allocator = allocator,
    };
}

/// Deinitializes the server.
pub fn deinit(self: *Self) void {
    _ = self;
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

/// Returns true if the method is a valid method for the given class.
fn isMethodAllowedForClass(method: ztun.Method, class: ztun.Class) bool {
    return switch (class) {
        .request => method == .binding,
        .indication => method == .binding,
        .success_response => method == .binding,
        .error_response => method == .binding,
    };
}

/// Checks that the given message bears the correct fingerprint. Returns true if so, false otherwise.
/// In case of any error, the function returns false.
fn checkFingerprint(message: ztun.Message, allocator: std.mem.Allocator) bool {
    var fingerprint = for (message.attributes) |a, i| {
        if (a.type == @as(u16, attr.Type.fingerprint)) {
            const fingerprint_attribute = attr.common.Fingerprint.fromAttribute(a) catch return false;
            if (i != message.attributes.len - 1) return false;
            break fingerprint_attribute.value;
        }
    } else return true;

    const fingerprint_message = ztun.Message.fromParts(message.type.class, message.type.method, message.transaction_id, message.attributes[0 .. message.attributes.len - 1]);
    const computed_fingerprint = fingerprint_message.computeFingerprint(allocator) catch return false;
    return computed_fingerprint == fingerprint;
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

/// Represents the parameters required to compute the authentication-related value.
const Authentication = union(AuthenticationType) {
    /// No parameters required when there is no authentication.
    none: void,
    /// Short-term authentication paramters.
    short_term: ztun.auth.ShortTermAuthentication,
    /// Long-term authentication paramters.
    long_term: ztun.auth.LongTermAuthentication,

    /// Returns a `ztun.auth.Authentication` struct from the server-specific `Authentication` struct.
    // TODO(Corendos): Find a better name for that or merge this and `ztun.auth.Authentication`.
    pub fn toAuthentication(self: Authentication) !ztun.auth.Authentication {
        return switch (self) {
            .none => error.InvalidAuthentication,
            .short_term => |short_term| ztun.auth.Authentication{ .short_term = short_term },
            .long_term => |long_term| ztun.auth.Authentication{ .long_term = long_term },
        };
    }
};

/// Represents the result of an authentication to the server.
const AuthenticationResult = union(enum) {
    /// The message should be discarded silently,
    discard: void,
    /// The authentication succeeded and the result contains the parameters.
    authentication: Authentication,
    /// The authentication failed and produced a response to send back.
    response: ztun.Message,
};

/// Type of Authentication result.
const AuthenticationResultType = std.meta.Tag(AuthenticationResult);

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
        for (attributes) |attribute, i| {
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

/// Checks that the message integrity stored in a STUN message is valid using the authentication parameters of a user. Returns true if the message integrity is corrext, false otherwise.
fn checkMessageIntegrity(message: ztun.Message, message_integrity_details: MessageIntegrityDetails, authentication: ztun.auth.Authentication, allocator: std.mem.Allocator) !bool {
    const key = try authentication.computeKeyAlloc(allocator);
    defer allocator.free(key);

    if (message_integrity_details.sha256_index) |index| {
        const computed_message_integrity = try ztun.Message.fromParts(message.type.class, message.type.method, message.transaction_id, message.attributes[0..index])
            .computeMessageIntegritySha256(allocator, key);
        const message_integrity_sha256_attribute = try attr.common.MessageIntegritySha256.fromAttribute(message.attributes[index]);
        const length = message_integrity_sha256_attribute.length;
        const message_integrity = message_integrity_sha256_attribute.storage[0..length];
        return std.mem.eql(u8, message_integrity, computed_message_integrity);
    } else if (message_integrity_details.simple_index) |index| {
        const computed_message_integrity = try ztun.Message.fromParts(message.type.class, message.type.method, message.transaction_id, message.attributes[0..index])
            .computeMessageIntegrity(allocator, key);
        const message_integrity_attribute = try attr.common.MessageIntegrity.fromAttribute(message.attributes[index]);
        const message_integrity = message_integrity_attribute.value[0..20];
        return std.mem.eql(u8, message_integrity, computed_message_integrity);
    } else unreachable;
}

/// Returns the credentials of a given user or null if there is none.
fn authenticateUser(self: Self, username: []const u8) ?ztun.auth.Authentication {
    if (!std.mem.eql(u8, username, "anon")) return null;
    // TODO(Corentin): implement checking
    const password = "password";
    return switch (self.options.authentication_type) {
        .short_term => ztun.auth.Authentication{ .short_term = ztun.auth.ShortTermAuthentication{ .password = password } },
        .long_term => ztun.auth.Authentication{ .long_term = ztun.auth.LongTermAuthentication{ .username = username, .password = password, .realm = "realm" } },
        else => unreachable,
    };
}

/// Authenticates the sender of a STUN message using the short-term mechanism.
fn authenticateShortTerm(self: Self, message: ztun.Message, message_integrity_details: MessageIntegrityDetails, temporary_allocator: std.mem.Allocator, allocator: std.mem.Allocator) !AuthenticationResult {
    if (!message_integrity_details.isValid()) {
        return .{ .response = try makeBadRequestMessage(message, allocator) };
    }

    const authentication = self.authenticateUser(message.attributes[message_integrity_details.username_index.?].data) orelse {
        if (message.type.class == .indication) {
            return .{ .discard = {} };
        } else if (message.type.class == .request) {
            return .{ .response = try makeUnauthenticatedMessage(message, "Unauthenticated", allocator) };
        } else unreachable;
    };

    if (!try checkMessageIntegrity(message, message_integrity_details, authentication, temporary_allocator)) {
        if (message.type.class == .indication) {
            return .{ .discard = {} };
        } else if (message.type.class == .request) {
            return .{ .response = try makeUnauthenticatedMessage(message, "Unauthenticated", allocator) };
        }
    }

    return .{ .authentication = Authentication{ .short_term = authentication.short_term } };
}

/// Authenticates the sender of a STUN message using the long-erm mechanism.
fn authenticateLongTerm(self: Self, message: ztun.Message, message_integrity_details: MessageIntegrityDetails, temporary_allocator: std.mem.Allocator, allocator: std.mem.Allocator) !AuthenticationResult {
    _ = message_integrity_details;
    _ = allocator;
    _ = temporary_allocator;
    _ = message;
    _ = self;
    @panic("Long-Term authentication is not implemented.");
}

/// Authenticates the sender of a STUN message using the server configuration.
fn authenticate(self: Self, message: ztun.Message, message_integrity_details: MessageIntegrityDetails, temporary_allocator: std.mem.Allocator, allocator: std.mem.Allocator) !AuthenticationResult {
    return switch (self.options.authentication_type) {
        .none => .{ .authentication = .{ .none = {} } },
        .short_term => self.authenticateShortTerm(message, message_integrity_details, temporary_allocator, allocator),
        .long_term => self.authenticateLongTerm(message, message_integrity_details, temporary_allocator, allocator),
    };
}

/// Handles a request after the basic checks and authentication (if needed) has been done.
pub fn handleRequest(server: Self, message: ztun.Message, source: net.Address, authentication: Authentication, message_integrity_details: MessageIntegrityDetails, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) Error!MessageResult {
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

    const xor_mapped_address_attribute = switch (source) {
        .ipv4 => |ipv4| blk: {
            const xor_mapped_address_attribute = attr.common.encode(attr.common.MappedAddress{
                .port = ipv4.port,
                .family = attr.common.AddressFamily{ .ipv4 = ipv4.value },
            }, message.transaction_id);
            break :blk try xor_mapped_address_attribute.toAttribute(allocator);
        },

        .ipv6 => |ipv6| blk: {
            const xor_mapped_address_attribute = attr.common.encode(attr.common.MappedAddress{
                .port = ipv6.port,
                .family = attr.common.AddressFamily{ .ipv6 = ipv6.value },
            }, message.transaction_id);
            break :blk try xor_mapped_address_attribute.toAttribute(allocator);
        },
    };
    errdefer allocator.free(xor_mapped_address_attribute.data);
    try message_builder.addAttribute(xor_mapped_address_attribute);

    const software_attribute = try software_version_attribute.toAttribute(allocator);
    errdefer allocator.free(software_attribute.data);
    try message_builder.addAttribute(software_attribute);

    if (authentication != .none) {
        const real_authentication = authentication.toAuthentication() catch unreachable;
        if (message_integrity_details.sha256_index != null) {
            message_builder.addMessageIntegritySha256(real_authentication);
        } else if (message_integrity_details.simple_index != null) {
            message_builder.addMessageIntegrity(real_authentication);
        } else unreachable;
    }

    message_builder.addFingerprint();
    return .{ .response = try message_builder.build() };
}

/// Handles an indication after the basic checks and authentication (if needed) has been done.
pub fn handleIndication(server: Self, message: ztun.Message, authentication: Authentication, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) Error!MessageResult {
    _ = authentication;
    _ = temporary_arena;
    _ = message;
    _ = allocator;
    _ = server;
    @panic("Indication handling is not implemented");
}

/// Handles a response after the basic checks and authentication (if needed) has been done.
pub fn handleResponse(server: Self, message: ztun.Message, success: bool, authentication: Authentication, temporary_arena: std.mem.Allocator, allocator: std.mem.Allocator) Error!MessageResult {
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
pub fn handleMessage(self: Self, message: ztun.Message, source: net.Address, allocator: std.mem.Allocator) !MessageResult {
    var temp_arena_state = std.heap.ArenaAllocator.init(self.allocator);
    defer temp_arena_state.deinit();

    // NOTE(Corendos): If the message has been successfully decoded, some basic checks already have been done.

    // Check that the method is allowed for the given class. If not, discard message as described in Section 6.3.
    if (!isMethodAllowedForClass(message.type.method, message.type.class)) return .{ .discard = {} };

    // Check the fingerprint if it's present
    if (!checkFingerprint(message, temp_arena_state.allocator())) return .{ .discard = {} };

    const message_integrity_details = MessageIntegrityDetails.fromAttributes(message.attributes);

    // Check authentication
    const authentication_result = self.authenticate(message, message_integrity_details, temp_arena_state.allocator(), allocator) catch return .{ .discard = {} };
    const authentication = switch (authentication_result) {
        .discard => return .{ .discard = {} },
        .response => |response| return .{ .response = response },
        .authentication => |authentication| authentication,
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
