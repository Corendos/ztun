// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

const io = @import("io.zig");
const Message = @import("lib.zig").Message;
const MessageType = @import("lib.zig").MessageType;
const Attribute = @import("attributes.zig").Attribute;
const AttributeType = @import("attributes.zig").AttributeType;

const magic_cookie = @import("constants.zig").magic_cookie;

pub const Error = error{
    OutOfMemory,
    EndOfStream,
    NotImplemented,
    NonZeroStartingBits,
    WrongMagicCookie,
    UnsupportedMethod,
    UnknownAttribute,
    InvalidAttributeFormat,
};

pub const UnknownAttribute = struct {
    value: u16,
    length: u16,
    data: []const u8,

    pub fn deinit(self: *const UnknownAttribute, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

pub const DeserializedAttribute = union(enum) {
    unknown: UnknownAttribute,
    known: Attribute,

    pub fn deinit(self: *const DeserializedAttribute, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .unknown => |value| value.deinit(allocator),
            .known => |value| value.deinit(allocator),
        }
    }
};

pub const DeserializedMessage = struct {
    @"type": MessageType,
    transaction_id: u96,
    length: u16,
    attributes: []const DeserializedAttribute,

    pub fn deinit(self: DeserializedMessage, allocator: std.mem.Allocator) void {
        for (self.attributes) |attribute| {
            attribute.deinit(allocator);
        }
        allocator.free(self.attributes);
    }

    pub fn toMessage(self: *const DeserializedMessage, allocator: std.mem.Allocator) !Message {
        for (self.attributes) |a| {
            if (a == .unknown) return error.UnknownAttribute;
        }

        var attribute_list = try std.ArrayList(Attribute).initCapacity(allocator, self.attributes.len);
        defer attribute_list.deinit();

        for (self.attributes) |a| {
            attribute_list.appendAssumeCapacity(a.known);
        }

        return Message{
            .type = self.type,
            .transaction_id = self.transaction_id,
            .length = self.length,
            .attributes = attribute_list.toOwnedSlice(),
        };
    }
};

fn readMessageType(reader: anytype) Error!MessageType {
    const raw_message_type: u16 = try reader.readIntBig(u16);
    if (raw_message_type & 0b1100_0000_0000_0000 != 0) {
        return error.NonZeroStartingBits;
    }
    return MessageType.tryFromInteger(@truncate(u14, raw_message_type)) orelse error.UnsupportedMethod;
}

fn readAttribute(reader: anytype, attribute_type: AttributeType, length: u16, allocator: std.mem.Allocator) !Attribute {
    return switch (attribute_type) {
        inline else => |tag| blk: {
            const Type = std.meta.TagPayload(Attribute, tag);
            break :blk @unionInit(Attribute, @tagName(tag), try Type.deserializeAlloc(reader, length, allocator));
        },
    };
}

pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) Error!DeserializedMessage {
    var deserialized_attribute_list = std.ArrayList(DeserializedAttribute).init(allocator);
    defer {
        for (deserialized_attribute_list.items) |a| {
            a.deinit(allocator);
        }
        deserialized_attribute_list.deinit();
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
        if (std.meta.intToEnum(AttributeType, raw_attribute_type)) |attribute_type| {
            const attribute = try readAttribute(attribute_reader_state.reader(), attribute_type, attribute_length, allocator);
            try deserialized_attribute_list.append(DeserializedAttribute{ .known = attribute });
        } else |_| {
            const data = try allocator.alloc(u8, attribute_length);
            errdefer allocator.free(data);
            try io.readNoEofAligned(attribute_reader_state.reader(), 4, data);
            try deserialized_attribute_list.append(DeserializedAttribute{
                .unknown = UnknownAttribute{
                    .value = raw_attribute_type,
                    .length = attribute_length,
                    .data = data,
                },
            });
        }
    }

    return DeserializedMessage{
        .type = message_type,
        .transaction_id = transaction_id,
        .length = message_length,
        .attributes = deserialized_attribute_list.toOwnedSlice(),
    };
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
    const message = try deserialize(stream.reader(), std.testing.allocator);
    defer message.deinit(std.testing.allocator);

    try std.testing.expectEqual(MessageType{ .class = .request, .method = .binding }, message.type);
    try std.testing.expectEqual(@as(u96, 0x0102030405060708090A0B), message.transaction_id);
    try std.testing.expectEqual(@as(usize, 1), message.attributes.len);
    try std.testing.expect(message.attributes[0] == .unknown);
    try std.testing.expectEqual(@as(u16, 0x0032), message.attributes[0].unknown.value);
    try std.testing.expectEqual(@as(u16, 0x0004), message.attributes[0].unknown.length);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x04 }, message.attributes[0].unknown.data);
}
