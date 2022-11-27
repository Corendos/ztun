// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const attr = @import("attributes.zig");
pub const io = @import("io.zig");
pub const fmt = @import("fmt.zig");
pub const auth = @import("authentication.zig");

const magic_cookie = @import("constants.zig").magic_cookie;
const fingerprint_magic = @import("constants.zig").fingerprint_magic;

pub const Method = enum(u12) {
    binding = 0b000000000001,
};

pub const Class = enum(u2) {
    request = 0b00,
    indication = 0b01,
    success_response = 0b10,
    error_response = 0b11,
};

pub const MessageType = struct {
    class: Class,
    method: Method,

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

pub const Attribute = union(attr.Type) {
    mapped_address: attr.MappedAddress,
    xor_mapped_address: attr.XorMappedAddress,
    username: attr.Username,
    userhash: attr.Userhash,
    message_integrity: attr.MessageIntegrity,
    message_integrity_sha256: attr.MessageIntegritySha256,
    fingerprint: attr.Fingerprint,
    error_code: attr.ErrorCode,
    realm: attr.Realm,
    nonce: attr.Nonce,
    password_algorithms: attr.PasswordAlgorithms,
    password_algorithm: attr.PasswordAlgorithm,
    unknown_attributes: attr.UnknownAttributes,
    software: attr.Software,
    alternate_server: attr.AlternateServer,
    alternate_domain: attr.AlternateDomain,

    pub fn alignedSize(self: *const Attribute) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const Attribute) usize {
        return 4 + switch (self.*) {
            inline else => |attribute| attribute.alignedSize(),
        };
    }

    pub fn serialize(self: *const Attribute, writer: anytype) !void {
        return switch (self.*) {
            inline else => |attribute, tag| {
                try writer.writeIntBig(u16, @enumToInt(tag));
                try writer.writeIntBig(u16, @truncate(u16, attribute.size()));
                try attribute.serialize(writer);
            },
        };
    }

    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) !Attribute {
        const raw_attribute_type = try reader.readIntBig(u16);
        const attribute_length = try reader.readIntBig(u16);
        const attribute_type = std.meta.intToEnum(attr.Type, raw_attribute_type) catch return error.UnknownAttribute;

        return switch (attribute_type) {
            inline else => |tag| @unionInit(Attribute, @tagName(tag), try std.meta.TagPayload(Attribute, tag).deserializeAlloc(reader, attribute_length, allocator)),
        };
    }

    pub fn deinit(self: *const Attribute, allocator: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |attribute| attribute.deinit(allocator),
        }
    }
};

pub const RawAttribute = struct {
    value: u16,
    length: u16,
    data: []const u8,

    pub fn alignedSize(self: *const RawAttribute) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const RawAttribute) usize {
        return 4 + self.length;
    }

    pub fn deinit(self: *const RawAttribute, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }

    pub fn serialize(self: *const RawAttribute, writer: anytype) !void {
        try writer.writeIntBig(u16, self.value);
        try writer.writeIntBig(u16, self.length);
        try io.writeAllAligned(self.data, 4, writer);
    }
};

pub const GenericAttribute = union(enum) {
    raw: RawAttribute,
    known: Attribute,

    pub fn alignedSize(self: *const GenericAttribute) usize {
        return switch (self.*) {
            inline else => |a| a.alignedSize(),
        };
    }

    pub fn size(self: *const GenericAttribute) usize {
        return switch (self.*) {
            inline else => |a| a.size(),
        };
    }

    pub fn deinit(self: *const GenericAttribute, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .raw => |value| value.deinit(allocator),
            .known => |value| value.deinit(allocator),
        }
    }

    pub fn serialize(self: *const GenericAttribute, writer: anytype) !void {
        return switch (self.*) {
            .raw => |value| value.serialize(writer),
            .known => |value| value.serialize(writer),
        };
    }
};

pub const DeserializationError = error{
    OutOfMemory,
    EndOfStream,
    NotImplemented,
    NonZeroStartingBits,
    WrongMagicCookie,
    UnsupportedMethod,
    UnknownAttribute,
    InvalidAttributeFormat,
};

pub const Message = struct {
    const Self = @This();

    @"type": MessageType,
    transaction_id: u96,
    length: u16,
    attributes: []const GenericAttribute,

    pub fn fromParts(class: Class, method: Method, transaction_id: u96, attributes: []const GenericAttribute) Self {
        var length: u16 = 0;
        for (attributes) |attribute| {
            length += @truncate(u16, attribute.alignedSize());
        }

        return Message{
            .type = MessageType{ .class = class, .method = method },
            .transaction_id = transaction_id,
            .length = length,
            .attributes = attributes,
        };
    }

    pub fn deinit(self: *const Self, allocator: std.mem.Allocator) void {
        for (self.attributes) |a| {
            a.deinit(allocator);
        }
        allocator.free(self.attributes);
    }

    fn writeHeader(self: *const Self, writer: anytype) !void {
        try writer.writeIntBig(u16, @intCast(u16, self.@"type".toInteger()));
        try writer.writeIntBig(u16, @truncate(u16, self.length));
        try writer.writeIntBig(u32, magic_cookie);
        try writer.writeIntBig(u96, self.transaction_id);
    }

    fn writeAttributes(self: *const Self, writer: anytype) !void {
        for (self.attributes) |attribute| {
            try attribute.serialize(writer);
        }
    }

    pub fn serialize(self: *const Self, writer: anytype) !void {
        try self.writeHeader(writer);
        try self.writeAttributes(writer);
    }

    pub fn computeFingerprint(self: *const Self, allocator: std.mem.Allocator) !u32 {
        var buffer = try allocator.alloc(u8, 2048);
        defer allocator.free(buffer);

        var message = self.*;
        // Take fingerprint into account
        message.length += 8;
        var stream = std.io.fixedBufferStream(buffer);
        try message.serialize(stream.writer());
        return std.hash.Crc32.hash(stream.getWritten()) ^ @as(u32, fingerprint_magic);
    }

    pub fn computeMessageIntegrity(self: *const Self, allocator: std.mem.Allocator, storage: *[20]u8, key: []const u8) ![]u8 {
        var buffer = try allocator.alloc(u8, 2048);
        defer allocator.free(buffer);

        var message = self.*;
        // Take message integrity into account
        message.length += 24;
        var stream = std.io.fixedBufferStream(buffer);
        message.serialize(stream.writer()) catch unreachable;
        std.crypto.auth.hmac.HmacSha1.create(storage, stream.getWritten(), key);
        return storage[0..20];
    }

    pub fn computeMessageIntegritySha256(self: *const Self, allocator: std.mem.Allocator, storage: *[32]u8, key: []const u8) ![]u8 {
        var buffer = try allocator.alloc(u8, 2048);
        defer allocator.free(buffer);

        var message = self.*;
        // Take message integrity into account
        message.length += 36;
        var stream = std.io.fixedBufferStream(buffer);
        message.serialize(stream.writer()) catch unreachable;
        const written = stream.getWritten();
        std.crypto.auth.hmac.sha2.HmacSha256.create(storage, written, key);
        return storage[0..];
    }

    fn readMessageType(reader: anytype) DeserializationError!MessageType {
        const raw_message_type: u16 = try reader.readIntBig(u16);
        if (raw_message_type & 0b1100_0000_0000_0000 != 0) {
            return error.NonZeroStartingBits;
        }
        return MessageType.tryFromInteger(@truncate(u14, raw_message_type)) orelse error.UnsupportedMethod;
    }

    fn readKnownAttribute(reader: anytype, attribute_type: attr.Type, length: u16, allocator: std.mem.Allocator) !Attribute {
        return switch (attribute_type) {
            inline else => |tag| blk: {
                const Type = std.meta.TagPayload(Attribute, tag);
                break :blk @unionInit(Attribute, @tagName(tag), try Type.deserializeAlloc(reader, length, allocator));
            },
        };
    }

    pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) DeserializationError!Message {
        var attribute_list = std.ArrayList(GenericAttribute).init(allocator);
        defer {
            for (attribute_list.items) |a| {
                a.deinit(allocator);
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
            const raw_attribute_type = try attribute_reader_state.reader().readIntBig(u16);
            const attribute_length = try attribute_reader_state.reader().readIntBig(u16);

            // TODO(Corentin): Might be useful to keep the original message, or at least some way to reconstruct it for fingerprint
            //                 check purposes.
            if (std.meta.intToEnum(attr.Type, raw_attribute_type)) |attribute_type| {
                const attribute = try readKnownAttribute(attribute_reader_state.reader(), attribute_type, attribute_length, allocator);
                try attribute_list.append(GenericAttribute{ .known = attribute });
            } else |_| {
                const data = try allocator.alloc(u8, attribute_length);
                errdefer allocator.free(data);
                try io.readNoEofAligned(attribute_reader_state.reader(), 4, data);
                try attribute_list.append(GenericAttribute{
                    .raw = RawAttribute{
                        .value = raw_attribute_type,
                        .length = attribute_length,
                        .data = data,
                    },
                });
            }
        }

        return Message{
            .type = message_type,
            .transaction_id = transaction_id,
            .length = message_length,
            .attributes = attribute_list.toOwnedSlice(),
        };
    }
};

pub const MessageBuilder = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    class: ?Class = null,
    method: ?Method = null,
    transaction_id: ?u96 = null,
    has_fingerprint: bool = false,
    message_integrity: ?auth.Authentication = null,
    message_integrity_sha256: ?auth.Authentication = null,
    attribute_list: std.ArrayList(GenericAttribute),

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .attribute_list = std.ArrayList(GenericAttribute).init(allocator),
        };
    }

    pub fn deinit(self: *const Self) void {
        self.attribute_list.deinit();
    }

    pub fn randomTransactionId(self: *Self) void {
        self.transaction_id = std.crypto.random.int(u96);
    }

    pub fn transactionId(self: *Self, transaction_id: u96) void {
        self.transaction_id = transaction_id;
    }

    pub fn setClass(self: *Self, class: Class) void {
        self.class = class;
    }

    pub fn setMethod(self: *Self, method: Method) void {
        self.method = method;
    }

    pub fn setHeader(self: *Self, method: Method, class: Class, transaction_id_opt: ?u96) void {
        self.setMethod(method);
        self.setClass(class);
        if (transaction_id_opt) |transaction_id| {
            self.transactionId(transaction_id);
        } else {
            self.randomTransactionId();
        }
    }

    pub fn addFingerprint(self: *Self) void {
        self.has_fingerprint = true;
    }

    pub fn addMessageIntegrity(self: *Self, parameters: auth.Authentication) void {
        self.message_integrity = parameters;
    }

    pub fn addMessageIntegritySha256(self: *Self, parameters: auth.Authentication) void {
        self.message_integrity_sha256 = parameters;
    }

    fn addGenericAttribute(self: *Self, attribute: GenericAttribute) !void {
        try self.attribute_list.append(attribute);
    }

    pub fn addAttribute(self: *Self, attribute: Attribute) !void {
        switch (attribute) {
            .fingerprint, .message_integrity, .message_integrity_sha256 => return error.InvalidAttribute,
            else => try self.addAttributeInternal(attribute),
        }
    }

    pub fn addRawAttribute(self: *Self, raw_attribute: RawAttribute) !void {
        return self.addGenericAttribute(GenericAttribute{ .unknown = raw_attribute });
    }

    fn isValid(self: *const Self) bool {
        if (self.class == null or self.method == null or self.transaction_id == null) return false;
        return true;
    }

    fn addAttributeInternal(self: *Self, attribute: Attribute) !void {
        try self.addGenericAttribute(GenericAttribute{ .known = attribute });
    }

    fn computeMessageIntegrity(self: *Self, parameters: auth.Authentication, allocator: std.mem.Allocator) !void {
        var storage: [20]u8 = undefined;
        const hmac_key = parameters.computeKey(&storage) catch unreachable;
        const message = Message.fromParts(self.class.?, self.method.?, self.transaction_id.?, self.attribute_list.items);
        const hmac = message.computeMessageIntegrity(allocator, &storage, hmac_key) catch unreachable;
        try self.addAttributeInternal(.{ .message_integrity = .{ .value = hmac[0..20].* } });
    }

    fn computeMessageIntegritySha256(self: *Self, parameters: auth.Authentication, allocator: std.mem.Allocator) !void {
        var storage: [32]u8 = undefined;
        const hmac_key = parameters.computeKey(&storage) catch unreachable;
        const message = Message.fromParts(self.class.?, self.method.?, self.transaction_id.?, self.attribute_list.items);
        const hmac = message.computeMessageIntegritySha256(allocator, &storage, hmac_key) catch unreachable;
        try self.addAttributeInternal(.{ .message_integrity_sha256 = attr.MessageIntegritySha256.fromRaw(hmac) catch unreachable });
    }

    pub fn build(self: *Self) !Message {
        if (!self.isValid()) return error.InvalidMessage;
        var buffer: [2048]u8 = undefined;
        var arena_state = std.heap.FixedBufferAllocator.init(&buffer);

        if (self.message_integrity) |parameters| {
            try self.computeMessageIntegrity(parameters, arena_state.allocator());
        }

        if (self.message_integrity_sha256) |parameters| {
            try self.computeMessageIntegritySha256(parameters, arena_state.allocator());
        }

        if (self.has_fingerprint) {
            const fingerprint = try Message.fromParts(self.class.?, self.method.?, self.transaction_id.?, self.attribute_list.items).computeFingerprint(arena_state.allocator());
            const attribute = GenericAttribute{ .known = Attribute{ .fingerprint = .{ .value = fingerprint } } };
            try self.attribute_list.append(attribute);
        }

        return Message.fromParts(self.class.?, self.method.?, self.transaction_id.?, self.attribute_list.toOwnedSlice());
    }
};

test "initialize indication message" {
    var message_builder = MessageBuilder.init(std.testing.allocator);
    defer message_builder.deinit();

    message_builder.setClass(.indication);
    message_builder.setMethod(.binding);
    message_builder.transactionId(0x42);
    const message = try message_builder.build();
    try std.testing.expectEqual(MessageType{ .class = .indication, .method = .binding }, message.type);
    try std.testing.expectEqual(@as(u96, 0x42), message.transaction_id);
}

test "initialize request message" {
    var message_builder = MessageBuilder.init(std.testing.allocator);
    defer message_builder.deinit();

    message_builder.setClass(.request);
    message_builder.setMethod(.binding);
    message_builder.transactionId(0x42);
    const message = try message_builder.build();
    try std.testing.expectEqual(MessageType{ .class = .request, .method = .binding }, message.type);
    try std.testing.expectEqual(@as(u96, 0x42), message.transaction_id);
}

test "initialize response message" {
    const success_response = blk: {
        var message_builder = MessageBuilder.init(std.testing.allocator);
        defer message_builder.deinit();

        message_builder.setClass(.success_response);
        message_builder.setMethod(.binding);
        message_builder.transactionId(0x42);
        break :blk try message_builder.build();
    };
    try std.testing.expectEqual(MessageType{ .class = .success_response, .method = .binding }, success_response.type);
    try std.testing.expectEqual(@as(u96, 0x42), success_response.transaction_id);
    const error_response = blk: {
        var message_builder = MessageBuilder.init(std.testing.allocator);
        defer message_builder.deinit();

        message_builder.setClass(.error_response);
        message_builder.setMethod(.binding);
        message_builder.transactionId(0x42);
        break :blk try message_builder.build();
    };
    try std.testing.expectEqual(MessageType{ .class = .error_response, .method = .binding }, error_response.type);
    try std.testing.expectEqual(@as(u96, 0x42), error_response.transaction_id);
}

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

test "attribute size" {
    const software_attribute = attr.Software{ .value = "abc" };
    const attribute = Attribute{ .software = software_attribute };
    try std.testing.expectEqual(@as(usize, 3), software_attribute.size());
    try std.testing.expectEqual(@as(usize, 8), attribute.size());
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
    try std.testing.expect(message.attributes[0] == .known);
    try std.testing.expect(message.attributes[0].known == attr.Type.fingerprint);
    try std.testing.expectEqual(@as(u32, 0x5b0ff6fc), message.attributes[0].known.fingerprint.value);
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
    const message = try Message.deserialize(stream.reader(), std.testing.allocator);
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(MessageType{ .class = .request, .method = .binding }, message.type);
    try std.testing.expectEqual(@as(u96, 0x0102030405060708090A0B), message.transaction_id);
    try std.testing.expectEqual(@as(usize, 1), message.attributes.len);
    try std.testing.expect(message.attributes[0] == .raw);
    try std.testing.expectEqual(@as(u16, 0x0032), message.attributes[0].raw.value);
    try std.testing.expectEqual(@as(u16, 0x0004), message.attributes[0].raw.length);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, message.attributes[0].raw.data);
}
