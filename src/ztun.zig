// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const fmt = @import("ztun/fmt.zig");
pub const deserialization = @import("ztun/deserialization.zig");

pub const Method = enum(u12) {
    binding = 0b000000000001,
};

pub const Class = enum(u2) {
    request = 0b00,
    indication = 0b01,
    success_response = 0b10,
    error_response = 0b11,
};

pub const magic_cookie = 0x2112A442;
pub const fingerprint_magic = 0x5354554e;
pub const message_header_length = 20;

fn writeAllAligned(bytes: []const u8, alignment: usize, writer: anytype) !void {
    try writer.writeAll(bytes);
    const padding = std.mem.alignForward(bytes.len, alignment) - bytes.len;
    try writer.writeByteNTimes(0, padding);
}

fn readNoEofAligned(reader: anytype, alignment: usize, buf: []u8) !void {
    try reader.readNoEof(buf);
    const padding = std.mem.alignForward(buf.len, alignment) - buf.len;
    try reader.skipBytes(@as(u64, padding), .{ .buf_size = 16 });
}

pub const AttributeType = enum(u16) {
    mapped_address = 0x0001,
    xor_mapped_address = 0x0020,
    username = 0x0006,
    userhash = 0x001E,
    message_integrity = 0x0008,
    message_integrity_sha256 = 0x001C,
    fingerprint = 0x8028,
    error_code = 0x0009,
    realm = 0x0014,
    nonce = 0x0015,
    password_algorithms = 0x8002,
    password_algorithm = 0x001D,
    unknown_attributes = 0x000A,
    software = 0x8022,
    alternate_server = 0x8023,
    alternate_domain = 0x8003,

    pub fn isComprehensionRequired(self: AttributeType) bool {
        const raw_value = @enumToInt(self);
        return 0x0000 <= raw_value and raw_value < 0x8000;
    }

    pub fn isComprehensionOptional(self: AttributeType) bool {
        return !self.isComprehensionRequired();
    }
};

pub const FamilyType = enum(u8) {
    ipv4 = 0x01,
    ipv6 = 0x02,
};

pub const Family = union(FamilyType) {
    ipv4: u32,
    ipv6: u128,

    pub fn size(self: Family) usize {
        return switch (self) {
            .ipv4 => 4,
            .ipv6 => 16,
        };
    }
};

pub const MappedAddressAttribute = struct {
    family: Family,
    port: u16,

    pub fn size(self: *const MappedAddressAttribute) usize {
        const raw_size: usize = 4 + self.family.size();
        return std.mem.alignForward(raw_size, 4);
    }

    pub fn serialize(self: *const MappedAddressAttribute, writer: anytype) !void {
        try writer.writeByte(0);
        switch (self.family) {
            inline else => |address, family| {
                try writer.writeByte(@enumToInt(family));
                try writer.writeIntBig(u16, self.port);
                try writer.writeIntBig(@TypeOf(address), address);
            },
        }
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !MappedAddressAttribute {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !MappedAddressAttribute {
        if (try reader.readByte() != 0x00) return error.InvalidAttributeFormat;
        const raw_family_type = try reader.readByte();
        const family_type = std.meta.intToEnum(FamilyType, raw_family_type) catch return error.InvalidAttributeFormat;
        const port = try reader.readIntBig(u16);

        const family = switch (family_type) {
            .ipv4 => Family{ .ipv4 = try reader.readIntBig(u32) },
            .ipv6 => Family{ .ipv6 = try reader.readIntBig(u128) },
        };

        return MappedAddressAttribute{
            .family = family,
            .port = port,
        };
    }

    pub fn deinit(self: *const MappedAddressAttribute, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const XorMappedAddressAttribute = struct {
    x_family: Family,
    x_port: u16,

    pub fn size(self: *const XorMappedAddressAttribute) usize {
        const raw_size: usize = 4 + self.x_family.size();

        return std.mem.alignForward(raw_size, 4);
    }

    pub fn serialize(self: *const XorMappedAddressAttribute, writer: anytype) !void {
        try writer.writeByte(0);
        switch (self.x_family) {
            inline else => |address, family| {
                try writer.writeByte(@enumToInt(family));
                try writer.writeIntBig(u16, self.x_port);
                try writer.writeIntBig(@TypeOf(address), address);
            },
        }
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !XorMappedAddressAttribute {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !XorMappedAddressAttribute {
        if (try reader.readByte() != 0x00) return error.InvalidAttributeFormat;
        const raw_family_type = try reader.readByte();
        const family_type = std.meta.intToEnum(FamilyType, raw_family_type) catch return error.InvalidAttributeFormat;
        const x_port = try reader.readIntBig(u16);

        const x_family = switch (family_type) {
            .ipv4 => Family{ .ipv4 = try reader.readIntBig(u32) },
            .ipv6 => Family{ .ipv6 = try reader.readIntBig(u128) },
        };

        return XorMappedAddressAttribute{
            .x_family = x_family,
            .x_port = x_port,
        };
    }

    pub fn deinit(self: *const XorMappedAddressAttribute, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }

    pub fn decode(self: *const XorMappedAddressAttribute, transaction_id: u96) MappedAddressAttribute {
        const port = self.x_port ^ @truncate(u16, (magic_cookie & 0xFFFF0000) >> 16);

        const family = switch (self.x_family) {
            .ipv4 => |address| Family{ .ipv4 = address ^ @as(u32, magic_cookie) },
            .ipv6 => |address| blk: {
                const mask: u128 = @as(u128, magic_cookie) << 96 | @as(u128, transaction_id);
                break :blk Family{ .ipv6 = address ^ mask };
            },
        };

        return MappedAddressAttribute{
            .port = port,
            .family = family,
        };
    }
};

pub const UsernameAttribute = struct {
    value: []const u8,

    pub fn size(self: *const UsernameAttribute) usize {
        return std.mem.alignForward(self.value.len, 4);
    }

    pub fn serialize(self: *const UsernameAttribute, writer: anytype) !void {
        try writeAllAligned(self.value, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !UsernameAttribute {
        var buffer = try allocator.alloc(u8, length);
        errdefer allocator.free(buffer);

        return UsernameAttribute.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !UsernameAttribute {
        try readNoEofAligned(reader, 4, buf);
        return UsernameAttribute{ .value = buf };
    }

    pub fn deinit(self: *const UsernameAttribute, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub const UserhashAttribute = struct {
    value: [32]u8,

    pub fn size(self: *const UserhashAttribute) usize {
        return std.mem.alignForward(self.value.len, 4);
    }

    pub fn serialize(self: *const UserhashAttribute, writer: anytype) !void {
        try writer.writeAll(&self.value);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !UserhashAttribute {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !UserhashAttribute {
        var self: UserhashAttribute = undefined;
        try reader.readNoEof(&self.value);
        return self;
    }

    pub fn deinit(self: *const UserhashAttribute, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const MessageIntegrityAttribute = struct {
    value: [20]u8,

    pub fn size(self: *const MessageIntegrityAttribute) usize {
        return std.mem.alignForward(self.value.len, 4);
    }

    pub fn serialize(self: *const MessageIntegrityAttribute, writer: anytype) !void {
        try writer.writeAll(&self.value);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !MessageIntegrityAttribute {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !MessageIntegrityAttribute {
        var self: MessageIntegrityAttribute = undefined;
        try reader.readNoEof(&self.value);
        return self;
    }

    pub fn deinit(self: *const MessageIntegrityAttribute, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const MessageIntegritySha256Attribute = struct {
    value: []const u8,

    pub fn size(self: *const MessageIntegritySha256Attribute) usize {
        return std.mem.alignForward(self.value.len, 4);
    }

    pub fn serialize(self: *const MessageIntegritySha256Attribute, writer: anytype) !void {
        std.debug.assert(std.mem.isAligned(self.value.len, 4));
        try writer.writeAll(self.value);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !MessageIntegritySha256Attribute {
        var buffer = try allocator.alloc(u8, length);
        errdefer allocator.free(buffer);

        return MessageIntegritySha256Attribute.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !MessageIntegritySha256Attribute {
        try reader.readNoEof(buf);
        return MessageIntegritySha256Attribute{ .value = buf };
    }

    pub fn deinit(self: *const MessageIntegritySha256Attribute, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub const FingerprintAttribute = struct {
    value: u32,

    pub fn size(self: *const FingerprintAttribute) usize {
        return std.mem.alignForward(@sizeOf(@TypeOf(self.value)), 4);
    }

    pub fn serialize(self: *const FingerprintAttribute, writer: anytype) !void {
        try writer.writeIntBig(u32, self.value);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !FingerprintAttribute {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !FingerprintAttribute {
        const value = try reader.readIntBig(u32);
        return FingerprintAttribute{ .value = value };
    }

    pub fn deinit(self: *const FingerprintAttribute, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const ErrorCodeAttribute = struct {
    value: u32,
    reason: []const u8,

    pub fn size(self: *const ErrorCodeAttribute) usize {
        const raw_size = 4 + self.reason.len;
        return std.mem.alignForward(raw_size, 4);
    }

    pub fn serialize(self: *const ErrorCodeAttribute, writer: anytype) !void {
        try writer.writeIntBig(u32, self.value);
        try writeAllAligned(self.reason, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !ErrorCodeAttribute {
        const reason_length = length - @sizeOf(u32);
        var buffer = try allocator.alloc(u8, reason_length);
        errdefer allocator.free(buffer);

        return ErrorCodeAttribute.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !ErrorCodeAttribute {
        const raw_class_and_number = try reader.readIntBig(u32);
        try readNoEofAligned(reader, 4, buf);
        return ErrorCodeAttribute{
            .value = raw_class_and_number,
            .reason = buf,
        };
    }

    pub fn deinit(self: *const ErrorCodeAttribute, allocator: std.mem.Allocator) void {
        allocator.free(self.reason);
    }
};

pub const RealmAttribute = struct {
    value: []const u8,

    pub fn size(self: *const RealmAttribute) usize {
        return std.mem.alignForward(self.value.len, 4);
    }

    pub fn serialize(self: *const RealmAttribute, writer: anytype) !void {
        try writeAllAligned(self.value, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !RealmAttribute {
        var buffer = try allocator.alloc(u8, length);
        errdefer allocator.free(buffer);

        return RealmAttribute.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !RealmAttribute {
        try readNoEofAligned(reader, 4, buf);
        return RealmAttribute{
            .value = buf,
        };
    }

    pub fn deinit(self: *const RealmAttribute, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub const NonceAttribute = struct {
    value: []const u8,

    pub fn size(self: *const NonceAttribute) usize {
        return std.mem.alignForward(self.value.len, 4);
    }

    pub fn serialize(self: *const NonceAttribute, writer: anytype) !void {
        try writeAllAligned(self.value, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !NonceAttribute {
        var buffer = try allocator.alloc(u8, length);
        errdefer allocator.free(buffer);

        return NonceAttribute.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !NonceAttribute {
        try readNoEofAligned(reader, 4, buf);
        return NonceAttribute{
            .value = buf,
        };
    }

    pub fn deinit(self: *const NonceAttribute, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub const PasswordAlgorithmType = enum {
    md5,
    sha256,
};

pub const PasswordAlgorithm = union(PasswordAlgorithmType) {
    md5: void,
    sha256: void,

    pub fn parameterSize(self: *const PasswordAlgorithm) usize {
        return switch (self.*) {
            .md5, .sha256 => 0,
        };
    }

    pub fn serialize(self: *const PasswordAlgorithm, writer: anytype) !void {
        switch (self.*) {
            .md5 => {
                try writer.writeIntBig(u16, 0x0001);
                try writer.writeIntBig(u16, 0);
            },
            .sha256 => {
                try writer.writeIntBig(u16, 0x0002);
                try writer.writeIntBig(u16, 0);
            },
        }
    }
};

pub const PasswordAlgorithmsAttribute = struct {
    algorithms: []PasswordAlgorithm,

    pub fn size(self: *const PasswordAlgorithmsAttribute) usize {
        var raw_size: usize = 0;
        for (self.algorithms) |algorithm| {
            raw_size += 4 + std.mem.alignForward(algorithm.parameterSize(), 4);
        }
        return std.mem.alignForward(raw_size, 4);
    }

    pub fn serialize(self: *const PasswordAlgorithmsAttribute, writer: anytype) !void {
        for (self.algorithms) |algorithm| {
            try algorithm.serialize(writer);
        }
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !PasswordAlgorithmsAttribute {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !PasswordAlgorithmsAttribute {
        _ = reader;
        return error.NotImplemented;
    }

    pub fn deinit(self: *const PasswordAlgorithmsAttribute, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const PasswordAlgorithmAttribute = struct {
    algorithm: PasswordAlgorithm,

    pub fn size(self: *const PasswordAlgorithmAttribute) usize {
        const raw_size = 4 + std.mem.alignForward(self.algorithm.parameterSize(), 4);
        return std.mem.alignForward(raw_size, 4);
    }

    pub fn serialize(self: *const PasswordAlgorithmAttribute, writer: anytype) !void {
        try self.algorithm.serialize(writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !PasswordAlgorithmAttribute {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !PasswordAlgorithmAttribute {
        _ = reader;
        return error.NotImplemented;
    }

    pub fn deinit(self: *const PasswordAlgorithmAttribute, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const UnknownAttribute = struct {
    attribute_types: []u16,

    pub fn size(self: *const UnknownAttribute) usize {
        const raw_size = self.attribute_types.len * @sizeOf(u16);
        return std.mem.alignForward(raw_size, 4);
    }

    pub fn serialize(self: *const UnknownAttribute, writer: anytype) !void {
        for (self.attribute_types) |attribute_type| {
            try writer.writeIntBig(u16, attribute_type);
        }
        if (self.attribute_types.len % 2 == 1) {
            try writer.writeIntBig(u16, 0);
        }
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !UnknownAttribute {
        if (length % 2 != 0) return error.InvalidAttributeFormat;
        var buffer = try allocator.alloc(u16, length / 2);
        errdefer allocator.free(buffer);

        return UnknownAttribute.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, attribute_types: []u16) !UnknownAttribute {
        for (attribute_types) |*attribute_type| {
            attribute_type.* = try reader.readIntBig(u16);
        }
        if (attribute_types.len % 2 == 1) {
            _ = try reader.readIntBig(u16);
        }
        return UnknownAttribute{ .attribute_types = attribute_types };
    }

    pub fn deinit(self: *const UnknownAttribute, allocator: std.mem.Allocator) void {
        allocator.free(self.attribute_types);
    }
};

pub const SoftwareAttribute = struct {
    value: []const u8,

    pub fn size(self: *const SoftwareAttribute) usize {
        return std.mem.alignForward(self.value.len, 4);
    }

    pub fn serialize(self: *const SoftwareAttribute, writer: anytype) !void {
        try writeAllAligned(self.value, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !SoftwareAttribute {
        var buffer = try allocator.alloc(u8, length);
        errdefer allocator.free(buffer);

        return SoftwareAttribute.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !SoftwareAttribute {
        try readNoEofAligned(reader, 4, buf);
        return SoftwareAttribute{
            .value = buf,
        };
    }

    pub fn deinit(self: *const SoftwareAttribute, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub const AlternateServerAttribute = struct {
    family: Family,
    port: u16,

    pub fn size(self: *const AlternateServerAttribute) usize {
        const raw_size: usize = 4 + self.family.size();
        return std.mem.alignForward(raw_size, 4);
    }

    pub fn serialize(self: *const AlternateServerAttribute, writer: anytype) !void {
        try writer.writeByte(0);
        switch (self.family) {
            inline else => |address, family| {
                try writer.writeByte(@enumToInt(family));
                try writer.writeIntBig(u16, self.port);
                try writer.writeIntBig(@TypeOf(address), address);
            },
        }
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !AlternateServerAttribute {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !AlternateServerAttribute {
        if (try reader.readByte() != 0x00) return error.InvalidAttributeFormat;
        const raw_family_type = try reader.readByte();
        const family_type = std.meta.intToEnum(FamilyType, raw_family_type) catch return error.InvalidAttributeFormat;
        const port = try reader.readIntBig(u16);

        const family = switch (family_type) {
            .ipv4 => Family{ .ipv4 = try reader.readIntBig(u32) },
            .ipv6 => Family{ .ipv6 = try reader.readIntBig(u128) },
        };

        return AlternateServerAttribute{
            .family = family,
            .port = port,
        };
    }

    pub fn deinit(self: *const AlternateServerAttribute, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const AlternateDomainAttribute = struct {
    value: []const u8,

    pub fn size(self: *const AlternateDomainAttribute) usize {
        return std.mem.alignForward(self.value.len, 4);
    }

    pub fn serialize(self: *const AlternateDomainAttribute, writer: anytype) !void {
        try writeAllAligned(self.value, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !AlternateDomainAttribute {
        var buffer = try allocator.alloc(u8, length);
        errdefer allocator.free(buffer);

        return AlternateDomainAttribute.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !AlternateDomainAttribute {
        try readNoEofAligned(reader, 4, buf);
        return AlternateDomainAttribute{
            .value = buf,
        };
    }

    pub fn deinit(self: *const AlternateDomainAttribute, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub const Attribute = union(AttributeType) {
    mapped_address: MappedAddressAttribute,
    xor_mapped_address: XorMappedAddressAttribute,
    username: UsernameAttribute,
    userhash: UserhashAttribute,
    message_integrity: MessageIntegrityAttribute,
    message_integrity_sha256: MessageIntegritySha256Attribute,
    fingerprint: FingerprintAttribute,
    error_code: ErrorCodeAttribute,
    realm: RealmAttribute,
    nonce: NonceAttribute,
    password_algorithms: PasswordAlgorithmsAttribute,
    password_algorithm: PasswordAlgorithmAttribute,
    unknown_attributes: UnknownAttribute,
    software: SoftwareAttribute,
    alternate_server: AlternateServerAttribute,
    alternate_domain: AlternateDomainAttribute,

    pub fn size(self: *const Attribute) usize {
        return 4 + switch (self.*) {
            inline else => |attribute| attribute.size(),
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
        const attribute_type = std.meta.intToEnum(AttributeType, raw_attribute_type) catch return error.UnknownAttribute;

        return switch (attribute_type) {
            inline else => |tag| blk: {
                const Type = std.meta.TagPayload(Attribute, tag);
                break :blk @unionInit(Attribute, @tagName(tag), try Type.deserializeAlloc(reader, attribute_length, allocator));
            },
        };
    }

    pub fn deinit(self: *const Attribute, allocator: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |attribute| attribute.deinit(allocator),
        }
    }
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

pub const MessageOptions = struct {
    transaction_id: ?u96 = null,
};

pub const Error = error{
    NonZeroStartingBits,
    WrongMagicCookie,
    UnsupportedMethod,
    UnknownAttribute,
    InvalidAttributeFormat,
};

pub const DeserializationError = Error || error{ OutOfMemory, EndOfStream, NotImplemented };

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

test "attribute size" {
    const software_attribute = SoftwareAttribute{ .value = "abc" };
    const attribute = Attribute{ .software = software_attribute };
    try std.testing.expectEqual(@as(usize, 4), software_attribute.size());
    try std.testing.expectEqual(@as(usize, 8), attribute.size());
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

test "write all aligned" {
    const str = [_]u8{ 1, 2, 3 };
    var buffer: [128]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try writeAllAligned(&str, 4, stream.writer());
    const written = stream.getWritten();
    try std.testing.expectEqual(@as(usize, 4), written.len);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 0 }, written);
}

test "read all aligned" {
    var buffer = [_]u8{0} ** 128;
    const str = "This is a test";
    std.mem.copy(u8, &buffer, str);
    var stream = std.io.fixedBufferStream(&buffer);

    var output_buffer: [str.len]u8 = undefined;
    try readNoEofAligned(stream.reader(), 4, &output_buffer);
    const pos = try stream.getPos();

    try std.testing.expectEqual(@as(usize, 16), pos);
    try std.testing.expectEqualSlices(u8, str, &output_buffer);
}

test "MAPPED-ADDRESS deserialization" {
    const buffer = [_]u8{
        // Padding
        0x00,
        // Family type
        0x01,
        // Port
        0x01,
        0x02,
        // Address
        127,
        0,
        0,
        1,
    };
    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try MappedAddressAttribute.deserialize(stream.reader());
    try std.testing.expectEqual(@as(u16, 0x0102), attribute.port);
    try std.testing.expectEqual(FamilyType.ipv4, attribute.family);
    try std.testing.expectEqual(@as(u32, 0x7F000001), attribute.family.ipv4);
}

test "UNKNOWN-ATTRIBUTES deserialization" {
    const buffer = [_]u8{
        // Type
        0x00, 0x0A,
        // Length
        0x00, 0x06,
        // UnknownAttributes
        0x00, 0x02,
        0x00, 0x03,
        0x00, 0x04,
        // Padding
        0x00, 0x00,
    };

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var stream = std.io.fixedBufferStream(&buffer);

    const attribute = try Attribute.deserialize(stream.reader(), arena_state.allocator());
    try std.testing.expect(attribute == .unknown_attributes);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 0x0002, 0x0003, 0x0004 }, attribute.unknown_attributes.attribute_types);
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
    try std.testing.expect(message.attributes[0] == AttributeType.fingerprint);
    try std.testing.expectEqual(@as(u32, 0x5b0ff6fc), message.attributes[0].fingerprint.value);
}

test {
    _ = @import("ztun/deserialization.zig");
}
