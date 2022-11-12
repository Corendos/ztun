// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const Attribute = @import("attributes.zig").Attribute;
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

pub const Message = struct {
    const Self = @This();

    @"type": MessageType,
    transaction_id: u96,
    length: u16,
    attributes: []const Attribute,

    pub fn fromParts(class: Class, method: Method, transaction_id: u96, attributes: []const Attribute) Self {
        var length: u16 = 0;
        for (attributes) |attribute| {
            length += @truncate(u16, attribute.size());
        }
        return Message{
            .type = MessageType{ .class = class, .method = method },
            .transaction_id = transaction_id,
            .length = length,
            .attributes = attributes,
        };
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
};

pub const MessageIntegrityType = enum {
    none,
    simple,
    sha256,
};

pub const MessageBuilder = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    class: ?Class = null,
    method: ?Method = null,
    transaction_id: ?u96 = null,
    has_fingerprint: bool = false,
    message_integrity_type: MessageIntegrityType = .none,
    attribute_list: std.ArrayList(Attribute),

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .attribute_list = std.ArrayList(Attribute).init(allocator),
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

    pub fn addFingerprint(self: *Self) void {
        self.has_fingerprint = true;
    }

    pub fn addMessageIntegrity(self: *Self, message_integrity_type: MessageIntegrityType) void {
        self.message_integrity_type = message_integrity_type;
    }

    pub fn addAttribute(self: *Self, attribute: Attribute) !void {
        switch (attribute) {
            .fingerprint, .message_integrity, .message_integrity_sha256 => return error.InvalidAttribute,
            else => {
                try self.attribute_list.append(attribute);
            },
        }
    }

    fn isValid(self: *const Self) bool {
        return self.class != null and self.method != null and self.transaction_id != null;
    }

    fn computeFingerprint(self: *const Self) u32 {
        var buffer: [2048]u8 = undefined;

        var message = Message.fromParts(self.class.?, self.method.?, self.transaction_id.?, self.attribute_list.items);
        // Take fingerprint into account
        message.length += 8;
        var stream = std.io.fixedBufferStream(&buffer);
        message.serialize(stream.writer()) catch unreachable;
        return std.hash.Crc32.hash(stream.getWritten());
    }

    pub fn build(self: *Self) !Message {
        if (!self.isValid()) return error.InvalidMessage;
        if (self.has_fingerprint) {
            const hash = self.computeFingerprint();
            const fingerprint = hash ^ @as(u32, fingerprint_magic);
            try self.attribute_list.append(@unionInit(Attribute, "fingerprint", .{ .value = fingerprint }));
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

test "Message fingeprint" {
    const AttributeType = @import("attributes.zig").AttributeType;

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
    try std.testing.expect(message.attributes[0] == AttributeType.fingerprint);
    try std.testing.expectEqual(@as(u32, 0x5b0ff6fc), message.attributes[0].fingerprint.value);
}
