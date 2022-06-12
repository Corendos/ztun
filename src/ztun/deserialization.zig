// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const ztun = @import("../ztun.zig");
const Message = ztun.Message;
const MessageType = ztun.MessageType;
const Attribute = ztun.Attribute;
const AttributeType = ztun.AttributeType;
const Error = ztun.Error;

const RawUnknownAttribute = u16;

pub const DeserializationError = Error || error{ OutOfMemory, EndOfStream, NotImplemented };

const DeserializationResult = struct {
    message: Message,
    unknown_attributes: []RawUnknownAttribute,

    pub fn deinit(self: DeserializationResult, allocator: std.mem.Allocator) void {
        allocator.free(self.unknown_attributes);
        for (self.message.attributes) |attribute| {
            attribute.deinit(allocator);
        }
        allocator.free(self.message.attributes);
    }
};

fn readMessageType(reader: anytype) DeserializationError!MessageType {
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

pub fn deserialize(reader: anytype, allocator: std.mem.Allocator) DeserializationError!DeserializationResult {
    var unknown_attribute_list = std.ArrayList(RawUnknownAttribute).init(allocator);
    defer unknown_attribute_list.deinit();
    var attribute_list = std.ArrayList(Attribute).init(allocator);
    defer {
        for (attribute_list.items) |attribute| {
            attribute.deinit(allocator);
        }
        attribute_list.deinit();
    }

    const message_type = try readMessageType(reader);
    const message_length = try reader.readIntBig(u16);
    const message_magic = try reader.readIntBig(u32);
    if (message_magic != ztun.magic_cookie) return error.WrongMagicCookie;
    const transaction_id = try reader.readIntBig(u96);

    var attribute_reader_state = std.io.countingReader(reader);
    while (attribute_reader_state.bytes_read < message_length) {
        const raw_attribute_type = try attribute_reader_state.reader().readIntBig(u16);
        const attribute_length = try attribute_reader_state.reader().readIntBig(u16);

        if (std.meta.intToEnum(AttributeType, raw_attribute_type)) |attribute_type| {
            const attribute = try readAttribute(attribute_reader_state.reader(), attribute_type, attribute_length, allocator);
            try attribute_list.append(attribute);
        } else |_| {
            try unknown_attribute_list.append(raw_attribute_type);
            try attribute_reader_state.reader().skipBytes(attribute_length, .{ .buf_size = 16 });
        }
    }

    return DeserializationResult{
        .message = Message.fromParts(message_type.class, message_type.method, transaction_id, attribute_list.toOwnedSlice()),
        .unknown_attributes = unknown_attribute_list.toOwnedSlice(),
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
    const result = try deserialize(stream.reader(), std.testing.allocator);
    defer result.deinit(std.testing.allocator);

    try std.testing.expectEqual(MessageType{ .class = .request, .method = .binding }, result.message.type);
    try std.testing.expectEqual(@as(u96, 0x0102030405060708090A0B), result.message.transaction_id);
    try std.testing.expectEqual(@as(usize, 0), result.message.attributes.len);
    try std.testing.expectEqualSlices(RawUnknownAttribute, &.{0x0032}, result.unknown_attributes);
}
