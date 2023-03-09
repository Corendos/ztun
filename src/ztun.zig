// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const attr = @import("ztun/attributes.zig");
pub const io = @import("ztun/io.zig");
pub const net = @import("ztun/net.zig");
pub const fmt = @import("ztun/fmt.zig");
pub const auth = @import("ztun/authentication.zig");
pub const constants = @import("ztun/constants.zig");

pub const magic_cookie = constants.magic_cookie;
pub const fingerprint_magic = constants.fingerprint_magic;

pub const Attribute = attr.Attribute;
pub const Server = @import("ztun/Server.zig");

/// Represents the method used in the message. The RFC originally defined only the "binding" method.
pub const Method = enum(u12) {
    binding = 0b000000000001,
};

/// Represents the class of the message.
pub const Class = enum(u2) {
    request = 0b00,
    indication = 0b01,
    success_response = 0b10,
    error_response = 0b11,
};

/// Represents the Message Type field of the STUN message header, as defined in Section 5 of the RFC.
pub const MessageType = struct {
    class: Class,
    method: Method,

    /// Converts the message type to its integer representation.
    pub fn toInteger(self: MessageType) u14 {
        const raw_class = @intCast(u14, @enumToInt(self.class));
        const raw_method = @intCast(u14, @enumToInt(self.method));

        var raw_value: u14 = 0;
        raw_value |= (raw_method & 0b1111);
        raw_value |= (raw_method & 0b1110000) << 1;
        raw_value |= (raw_method & 0b111110000000) << 2;
        raw_value |= (raw_class & 0b1) << 4;
        raw_value |= (raw_class & 0b10) << 7;

        return raw_value;
    }

    /// Tries to extract a valid Message Type from an input integer. Returns null on failure.
    pub fn tryFromInteger(value: u14) ?MessageType {
        var raw_class = (value & 0b10000) >> 4;
        raw_class |= (value & 0b100000000) >> 7;

        var raw_method = (value & 0b1111);
        raw_method |= (value & 0b11100000) >> 1;
        raw_method |= (value & 0b11111000000000) >> 2;

        const class = @intToEnum(Class, @truncate(u2, raw_class));
        const method = std.meta.intToEnum(Method, @truncate(u12, raw_method)) catch return null;
        return MessageType{
            .class = class,
            .method = method,
        };
    }
};

test "message type to integer" {
    {
        const message_type = MessageType{ .class = .request, .method = .binding };
        const message_type_as_u16 = @intCast(u16, message_type.toInteger());
        try std.testing.expectEqual(@as(u16, 0x0001), message_type_as_u16);
    }
    {
        const message_type = MessageType{ .class = .success_response, .method = .binding };
        const message_type_as_u16 = @intCast(u16, message_type.toInteger());
        try std.testing.expectEqual(@as(u16, 0x0101), message_type_as_u16);
    }
}

test "integer to message type" {
    {
        const raw_message_type: u16 = 0x0001;
        const message_type = MessageType.tryFromInteger(@truncate(u14, raw_message_type));
        try std.testing.expect(message_type != null);
        try std.testing.expectEqual(MessageType{ .class = .request, .method = .binding }, message_type.?);
    }
    {
        const raw_message_type: u16 = 0x0101;
        const message_type = MessageType.tryFromInteger(@truncate(u14, raw_message_type));
        try std.testing.expect(message_type != null);
        try std.testing.expectEqual(MessageType{ .class = .success_response, .method = .binding }, message_type.?);
    }
}

/// Represents the type of message integrity to use.
pub const MessageIntegrityType = enum {
    /// Classical MESSAGE-INTEGRITY attribute.
    classic,
    /// MESSAGE-INTEGRITY-SHA256 attribute.
    sha256,
};

pub const DeserializationError = error{
    EndOfStream,
    NonZeroStartingBits,
    WrongMagicCookie,
    UnsupportedMethod,
} || std.mem.Allocator.Error;

/// Represents a STUN message.
pub const Message = struct {
    const Self = @This();

    /// The type of the message.
    type: MessageType,
    /// The transaction ID corresponding to this message.
    transaction_id: u96,
    /// The length in bytes of the message body (i.e not including the header length).
    length: u16,
    /// The list of attributes.
    attributes: []const Attribute,

    /// Creates a Message from its components. The length field is computed automatically using the size of the attribute payloads.
    pub fn fromParts(class: Class, method: Method, transaction_id: u96, attributes: []const Attribute) Self {
        var length: u16 = 0;
        for (attributes) |attribute| {
            length += @truncate(u16, attribute.length());
        }

        return Message{
            .type = MessageType{ .class = class, .method = method },
            .transaction_id = transaction_id,
            .length = length,
            .attributes = attributes,
        };
    }

    /// Handles the deallocation of the attribute list if it is owned by the message.
    /// This will free the data of each attribute and then free the attribute list.
    pub fn deinit(self: *const Self, allocator: std.mem.Allocator) void {
        for (self.attributes) |a| {
            allocator.free(a.data);
        }
        allocator.free(self.attributes);
    }

    /// Writes the header of the message to the given writer.
    fn writeHeader(self: *const Self, writer: anytype) !void {
        try writer.writeIntBig(u16, @intCast(u16, self.type.toInteger()));
        try writer.writeIntBig(u16, @truncate(u16, self.length));
        try writer.writeIntBig(u32, magic_cookie);
        try writer.writeIntBig(u96, self.transaction_id);
    }

    /// Writes the list of attributes to the given writer.
    fn writeAttributes(self: *const Self, writer: anytype) !void {
        for (self.attributes) |attribute| {
            try attr.write(attribute, writer);
        }
    }

    /// Writes the whole message to the given writer.
    pub fn write(self: *const Self, writer: anytype) !void {
        try self.writeHeader(writer);
        try self.writeAttributes(writer);
    }

    /// Computes the fingerprint value corresponding to the message. It computes the adjusted length value to produce a valid value.
    /// It returns a value that can be used directly in a FINGERPRINT attribute added to the list of attributes.
    /// This requires a temporary allocator to handle message serialization.
    pub fn computeFingerprint(self: *const Self, temp_allocator: std.mem.Allocator) error{OutOfMemory}!u32 {
        var buffer = try temp_allocator.alloc(u8, 2048);
        defer temp_allocator.free(buffer);

        var message = self.*;
        // Take fingerprint into account
        message.length += 8;
        var stream = std.io.fixedBufferStream(buffer);
        message.write(stream.writer()) catch unreachable;
        return std.hash.Crc32.hash(stream.getWritten()) ^ @as(u32, fingerprint_magic);
    }

    /// Computes the message integrity value corresponding to the message. It computes the adjusted length value to produce a valid value.
    /// It returns a value that can be used directly in a MESSAGE-INTEGRITY attribute added to the list of attributes.
    /// The storage for the returned value is allocated from the given allocator and ownership is granted.
    pub fn computeMessageIntegrity(self: *const Self, allocator: std.mem.Allocator, key: []const u8) error{OutOfMemory}![]u8 {
        var hmac_buffer = try allocator.alloc(u8, 20);
        errdefer allocator.free(hmac_buffer);

        var buffer = try allocator.alloc(u8, 2048);
        defer allocator.free(buffer);

        var message = self.*;
        // Take message integrity into account
        message.length += 24;
        var stream = std.io.fixedBufferStream(buffer);
        message.write(stream.writer()) catch unreachable;
        std.crypto.auth.hmac.HmacSha1.create(hmac_buffer[0..20], stream.getWritten(), key);
        return hmac_buffer[0..20];
    }

    /// Computes the SHA256 message integrity value corresponding to the message. It computes the adjusted length value to produce a valid value.
    /// It returns a value that can be used directly in a MESSAGE-INTEGRITY-SHA256 attribute added to the list of attributes.
    /// The storage for the returned value is allocated from the given allocator and ownership is granted.
    pub fn computeMessageIntegritySha256(self: *const Self, allocator: std.mem.Allocator, key: []const u8) error{OutOfMemory}![]u8 {
        var hmac_buffer = try allocator.alloc(u8, 32);
        errdefer allocator.free(hmac_buffer);

        var buffer = try allocator.alloc(u8, 2048);
        defer allocator.free(buffer);

        var message = self.*;
        // Take message integrity into account
        message.length += 36;
        var stream = std.io.fixedBufferStream(buffer);
        message.write(stream.writer()) catch unreachable;
        const written = stream.getWritten();
        std.crypto.auth.hmac.sha2.HmacSha256.create(hmac_buffer[0..32], written, key);
        return hmac_buffer[0..];
    }

    /// Tries to read the message type from the given reader. Returns a descriptive error on failure.
    fn readMessageType(reader: anytype) DeserializationError!MessageType {
        const raw_message_type: u16 = try reader.readIntBig(u16);
        if (raw_message_type & 0b1100_0000_0000_0000 != 0) {
            return error.NonZeroStartingBits;
        }
        return MessageType.tryFromInteger(@truncate(u14, raw_message_type)) orelse error.UnsupportedMethod;
    }

    /// Tries to read the message from the given reader, allocating the required storage from the allocator. Returns a descriptive error on failure.
    /// The returned message is the owner of the attribute list.
    pub fn readAlloc(reader: anytype, allocator: std.mem.Allocator) DeserializationError!Message {
        var attribute_list = std.ArrayList(Attribute).init(allocator);
        defer {
            for (attribute_list.items) |a| {
                allocator.free(a.data);
            }
            attribute_list.deinit();
        }

        const message_type = try readMessageType(reader);
        const message_length = try reader.readIntBig(u16);
        const message_magic = try reader.readIntBig(u32);
        if (message_magic != magic_cookie) return error.WrongMagicCookie;
        const transaction_id = try reader.readIntBig(u96);

        var attribute_reader_state = std.io.countingReader(reader);
        while (attribute_reader_state.bytes_read < message_length) {
            const attribute = try attr.readAlloc(attribute_reader_state.reader(), allocator);
            try attribute_list.append(attribute);
        }

        return Message{
            .type = message_type,
            .transaction_id = transaction_id,
            .length = message_length,
            .attributes = try attribute_list.toOwnedSlice(),
        };
    }

    /// Checks that the given message bears the correct fingerprint. Returns true if so, false otherwise.
    /// In case of any error, the function returns false.
    pub fn checkFingerprint(self: Self, allocator: std.mem.Allocator) bool {
        var fingerprint = for (self.attributes, 0..) |a, i| {
            if (a.type == @as(u16, attr.Type.fingerprint)) {
                const fingerprint_attribute = attr.common.Fingerprint.fromAttribute(a) catch return false;
                // The fingerprint attribute must be the last one.
                if (i != self.attributes.len - 1) return false;
                break fingerprint_attribute.value;
            }
        } else return true;

        const fingerprint_message = Self.fromParts(self.type.class, self.type.method, self.transaction_id, self.attributes[0 .. self.attributes.len - 1]);
        const computed_fingerprint = fingerprint_message.computeFingerprint(allocator) catch return false;
        return computed_fingerprint == fingerprint;
    }

    /// Checks that the message integrity stored in a STUN message is valid using the authentication parameters of a user. Returns true if the message integrity is correct, false otherwise.
    pub fn checkMessageIntegrity(message: Message, @"type": MessageIntegrityType, attribute_index: usize, key: []const u8, allocator: std.mem.Allocator) !bool {
        const truncated_message = Message.fromParts(message.type.class, message.type.method, message.transaction_id, message.attributes[0..attribute_index]);
        return switch (@"type") {
            .classic => r: {
                const computed_message_integrity = try truncated_message.computeMessageIntegrity(allocator, key);
                const message_integrity_attribute = try attr.common.MessageIntegrity.fromAttribute(message.attributes[attribute_index]);
                const message_integrity = message_integrity_attribute.value[0..20];
                break :r std.mem.eql(u8, message_integrity, computed_message_integrity);
            },
            .sha256 => r: {
                const computed_message_integrity = try truncated_message.computeMessageIntegritySha256(allocator, key);
                const message_integrity_sha256_attribute = try attr.common.MessageIntegritySha256.fromAttribute(message.attributes[attribute_index]);
                const length = message_integrity_sha256_attribute.length;
                const stored_message_integrity = message_integrity_sha256_attribute.storage[0..length];
                break :r std.mem.eql(u8, stored_message_integrity, computed_message_integrity);
            },
        };
    }
};

/// Convenience helper to build a message.
pub const MessageBuilder = struct {
    const Self = @This();

    pub const Error = error{ InvalidMessage, InvalidString, NoSpaceLeft } || std.mem.Allocator.Error;

    /// Allocator that will be used to allocate the required storage for the message.
    allocator: std.mem.Allocator,
    /// Class of the message.
    class: ?Class = null,
    /// Method of the message.
    method: ?Method = null,
    /// Transaction ID of the message.
    transaction_id: ?u96 = null,
    /// Flag representing the need to add a fingerprint to the message.
    has_fingerprint: bool = false,
    /// Stores the required parameters to compute the MESSAGE-INTEGRITY value of the message.
    message_integrity: ?auth.Authentication = null,
    /// Stores the required parameters to compute the MESSAGE-INTEGRITY-SHA256 value of the message.
    message_integrity_sha256: ?auth.Authentication = null,
    /// The list of attribute to add to the message.
    attribute_list: std.ArrayList(Attribute),

    /// Initializes a builder that will use the given allocator.
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .attribute_list = std.ArrayList(Attribute).init(allocator),
        };
    }

    /// Handles deallocation of everything that has been allocated to build the message and is no longer required.
    pub fn deinit(self: *const Self) void {
        self.attribute_list.deinit();
    }

    /// Adds a random transaction ID to the message.
    pub fn randomTransactionId(self: *Self) void {
        self.transaction_id = std.crypto.random.int(u96);
    }

    /// Adds a specific transaction ID to the message.
    pub fn transactionId(self: *Self, transaction_id: u96) void {
        self.transaction_id = transaction_id;
    }

    /// Sets the class of the message.
    pub fn setClass(self: *Self, class: Class) void {
        self.class = class;
    }

    /// Sets the method of the message.
    pub fn setMethod(self: *Self, method: Method) void {
        self.method = method;
    }

    /// Sets the header directly in one call. If the transaction ID is not given, a random one will be generated.
    pub fn setHeader(self: *Self, method: Method, class: Class, transaction_id_opt: ?u96) void {
        self.setMethod(method);
        self.setClass(class);
        if (transaction_id_opt) |transaction_id| {
            self.transactionId(transaction_id);
        } else {
            self.randomTransactionId();
        }
    }

    /// Adds a fingerprint to the message.
    pub fn addFingerprint(self: *Self) void {
        self.has_fingerprint = true;
    }

    /// Adds a MESSAGE-INTEGRITY attribute to the message.
    pub fn addMessageIntegrity(self: *Self, parameters: auth.Authentication) void {
        self.message_integrity = parameters;
    }

    /// Adds a MESSAGE-INTEGRITY-SHA256 attribute to the message.
    pub fn addMessageIntegritySha256(self: *Self, parameters: auth.Authentication) void {
        self.message_integrity_sha256 = parameters;
    }

    /// Adds an attribute to the message.
    pub fn addAttribute(self: *Self, attribute: Attribute) !void {
        try self.attribute_list.append(attribute);
    }

    /// Returns true if the message is sufficiently specified to be generated.
    fn isValid(self: *const Self) bool {
        if (self.class == null or self.method == null or self.transaction_id == null) return false;
        return true;
    }

    /// Compute the MESSAGE-INTEGRITY value of the message using the given parameters.
    /// It requires a temporary allocator to handle the serialization of the message.
    fn computeMessageIntegrity(self: *Self, parameters: auth.Authentication, temp_allocator: std.mem.Allocator) Error!void {
        const hmac_key = try parameters.computeKeyAlloc(temp_allocator);
        defer temp_allocator.free(hmac_key);

        var message_integrity_attribute: attr.common.MessageIntegrity = undefined;
        const message = Message.fromParts(self.class.?, self.method.?, self.transaction_id.?, self.attribute_list.items);
        const hmac = message.computeMessageIntegrity(temp_allocator, hmac_key) catch unreachable;
        std.mem.copy(u8, message_integrity_attribute.value[0..], hmac);

        const attribute = try message_integrity_attribute.toAttribute(self.allocator);
        errdefer self.allocator.free(attribute.data);

        try self.addAttribute(attribute);
    }

    /// Compute the MESSAGE-INTEGRITY-SHA256 value of the message using the given parameters.
    /// It requires a temporary allocator to handle the serialization of the message.
    fn computeMessageIntegritySha256(self: *Self, parameters: auth.Authentication, temp_allocator: std.mem.Allocator) Error!void {
        const hmac_key = try parameters.computeKeyAlloc(temp_allocator);
        defer temp_allocator.free(hmac_key);

        var message_integrity_sha256_attribute: attr.common.MessageIntegritySha256 = undefined;
        const message = Message.fromParts(self.class.?, self.method.?, self.transaction_id.?, self.attribute_list.items);
        const hmac = message.computeMessageIntegritySha256(temp_allocator, hmac_key) catch unreachable;
        std.mem.copy(u8, message_integrity_sha256_attribute.storage[0..], hmac);
        message_integrity_sha256_attribute.length = hmac.len;

        const attribute = try message_integrity_sha256_attribute.toAttribute(self.allocator);
        errdefer self.allocator.free(attribute.data);

        try self.addAttribute(attribute);
    }

    /// Tries to build a message using the currently set parameters. Returns a descriptive error in case of failure.
    /// The message is the owner of the allocation done using the builder's allocator.
    /// This takes care of adding the FINGERPRINT, MESSAGE-INTEGRITY(-SHA256) attributes to the message with the correct location and value.
    pub fn build(self: *Self) Error!Message {
        if (!self.isValid()) return error.InvalidMessage;
        var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena_state.deinit();

        if (self.message_integrity) |parameters| {
            try self.computeMessageIntegrity(parameters, arena_state.allocator());
        }

        if (self.message_integrity_sha256) |parameters| {
            try self.computeMessageIntegritySha256(parameters, arena_state.allocator());
        }

        if (self.has_fingerprint) {
            const fingerprint = try Message.fromParts(self.class.?, self.method.?, self.transaction_id.?, self.attribute_list.items).computeFingerprint(arena_state.allocator());
            const fingerprint_attribute = attr.common.Fingerprint{ .value = fingerprint };
            const attribute = try fingerprint_attribute.toAttribute(self.allocator);
            errdefer self.allocator.free(attribute.data);

            try self.attribute_list.append(attribute);
        }

        return Message.fromParts(self.class.?, self.method.?, self.transaction_id.?, try self.attribute_list.toOwnedSlice());
    }
};

/// Returns true if the method is a valid method for the given class.
pub fn isMethodAllowedForClass(method: Method, class: Class) bool {
    return switch (class) {
        .request => method == .binding,
        .indication => method == .binding,
        .success_response => method == .binding,
        .error_response => method == .binding,
    };
}

test "Message fingeprint" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    const message: Message = blk: {
        var message_builder = MessageBuilder.init(arena_state.allocator());
        defer message_builder.deinit();

        message_builder.setClass(.request);
        message_builder.setMethod(.binding);
        message_builder.transactionId(0x0102030405060708090A0B);
        message_builder.addFingerprint();
        break :blk try message_builder.build();
    };
    try std.testing.expectEqual(message.attributes.len, 1);
    try std.testing.expectEqual(@as(u16, attr.Type.fingerprint), message.attributes[0].type);
    try std.testing.expectEqualSlices(u8, message.attributes[0].data, &[_]u8{ 0x5b, 0x0f, 0xf6, 0xfc });
}

test "try to deserialize a message" {
    const bytes = [_]u8{
        // Type
        0x00, 0x01,
        // Length
        0x00, 0x08,
        // Magic Cookie
        0x21, 0x12,
        0xA4, 0x42,
        // Transaction ID
        0x00, 0x01,
        0x02, 0x03,
        0x04, 0x05,
        0x06, 0x07,
        0x08, 0x09,
        0x0A, 0x0B,
        // Unknown First Attribute
        0x00, 0x32,
        0x00, 0x04,
        0x01, 0x02,
        0x03, 0x04,
    };

    var stream = std.io.fixedBufferStream(&bytes);
    const message = try Message.readAlloc(stream.reader(), std.testing.allocator);
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(MessageType{ .class = .request, .method = .binding }, message.type);
    try std.testing.expectEqual(@as(u96, 0x0102030405060708090A0B), message.transaction_id);
    try std.testing.expectEqual(@as(usize, 1), message.attributes.len);
    try std.testing.expectEqual(@as(u16, 0x0032), message.attributes[0].type);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, message.attributes[0].data);
}

test {
    _ = std.testing.refAllDeclsRecursive(@This());
}
