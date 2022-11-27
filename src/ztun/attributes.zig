// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const io = @import("io.zig");
const magic_cookie = @import("constants.zig").magic_cookie;

pub fn isComprehensionRequiredRaw(value: u16) bool {
    return 0x000 <= value and value < 0x8000;
}

pub fn isComprehensionOptionalRaw(value: u16) bool {
    return !isComprehensionRequiredRaw(value);
}

pub const Type = enum(u16) {
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

    pub fn isComprehensionRequired(self: Type) bool {
        return isComprehensionRequiredRaw(@enumToInt(self));
    }

    pub fn isComprehensionOptional(self: Type) bool {
        return isComprehensionOptionalRaw(@enumToInt(self));
    }
};

pub const AddressFamilyType = enum(u8) {
    ipv4 = 0x01,
    ipv6 = 0x02,
};

pub const AddressFamily = union(AddressFamilyType) {
    ipv4: u32,
    ipv6: u128,

    pub fn size(self: AddressFamily) usize {
        return switch (self) {
            .ipv4 => 4,
            .ipv6 => 16,
        };
    }
};

pub const MappedAddress = struct {
    family: AddressFamily,
    port: u16,

    pub fn alignedSize(self: *const MappedAddress) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const MappedAddress) usize {
        return 4 + self.family.size();
    }

    pub fn serialize(self: *const MappedAddress, writer: anytype) !void {
        try writer.writeByte(0);
        switch (self.family) {
            inline else => |address, family| {
                try writer.writeByte(@enumToInt(family));
                try writer.writeIntBig(u16, self.port);
                try writer.writeIntBig(@TypeOf(address), address);
            },
        }
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !MappedAddress {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !MappedAddress {
        if (try reader.readByte() != 0x00) return error.InvalidAttributeFormat;
        const raw_family_type = try reader.readByte();
        const family_type = std.meta.intToEnum(AddressFamilyType, raw_family_type) catch return error.InvalidAttributeFormat;
        const port = try reader.readIntBig(u16);

        const family = switch (family_type) {
            .ipv4 => AddressFamily{ .ipv4 = try reader.readIntBig(u32) },
            .ipv6 => AddressFamily{ .ipv6 = try reader.readIntBig(u128) },
        };

        return MappedAddress{
            .family = family,
            .port = port,
        };
    }

    pub fn deinit(self: *const MappedAddress, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const XorMappedAddress = struct {
    x_family: AddressFamily,
    x_port: u16,

    pub fn alignedSize(self: *const XorMappedAddress) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const XorMappedAddress) usize {
        return 4 + self.x_family.size();
    }

    pub fn serialize(self: *const XorMappedAddress, writer: anytype) !void {
        try writer.writeByte(0);
        switch (self.x_family) {
            inline else => |address, family| {
                try writer.writeByte(@enumToInt(family));
                try writer.writeIntBig(u16, self.x_port);
                try writer.writeIntBig(@TypeOf(address), address);
            },
        }
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !XorMappedAddress {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !XorMappedAddress {
        if (try reader.readByte() != 0x00) return error.InvalidAttributeFormat;
        const raw_family_type = try reader.readByte();
        const family_type = std.meta.intToEnum(AddressFamilyType, raw_family_type) catch return error.InvalidAttributeFormat;
        const x_port = try reader.readIntBig(u16);

        const x_family = switch (family_type) {
            .ipv4 => AddressFamily{ .ipv4 = try reader.readIntBig(u32) },
            .ipv6 => AddressFamily{ .ipv6 = try reader.readIntBig(u128) },
        };

        return XorMappedAddress{
            .x_family = x_family,
            .x_port = x_port,
        };
    }

    pub fn deinit(self: *const XorMappedAddress, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }

    pub fn decode(self: *const XorMappedAddress, transaction_id: u96) MappedAddress {
        const port = self.x_port ^ @truncate(u16, (magic_cookie & 0xFFFF0000) >> 16);

        const family = switch (self.x_family) {
            .ipv4 => |address| AddressFamily{ .ipv4 = address ^ @as(u32, magic_cookie) },
            .ipv6 => |address| blk: {
                const mask: u128 = @as(u128, magic_cookie) << 96 | @as(u128, transaction_id);
                break :blk AddressFamily{ .ipv6 = address ^ mask };
            },
        };

        return MappedAddress{
            .port = port,
            .family = family,
        };
    }

    pub fn encode(mapped_address_attribute: MappedAddress, transaction_id: u96) XorMappedAddress {
        const x_port = mapped_address_attribute.port ^ @truncate(u16, (magic_cookie & 0xFFFF0000) >> 16);

        const x_family = switch (mapped_address_attribute.family) {
            .ipv4 => |address| AddressFamily{ .ipv4 = address ^ @as(u32, magic_cookie) },
            .ipv6 => |address| blk: {
                const mask: u128 = @as(u128, magic_cookie) << 96 | @as(u128, transaction_id);
                break :blk AddressFamily{ .ipv6 = address ^ mask };
            },
        };

        return XorMappedAddress{
            .x_port = x_port,
            .x_family = x_family,
        };
    }
};

pub const Username = struct {
    value: []const u8,

    pub fn alignedSize(self: *const Username) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const Username) usize {
        return self.value.len;
    }

    pub fn serialize(self: *const Username, writer: anytype) !void {
        try io.writeAllAligned(self.value, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !Username {
        var buffer = try allocator.alloc(u8, length);
        errdefer allocator.free(buffer);

        return Username.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !Username {
        try io.readNoEofAligned(reader, 4, buf);
        return Username{ .value = buf };
    }

    pub fn deinit(self: *const Username, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub const Userhash = struct {
    value: [32]u8,

    pub fn alignedSize(self: *const Userhash) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const Userhash) usize {
        return self.value.len;
    }

    pub fn serialize(self: *const Userhash, writer: anytype) !void {
        try writer.writeAll(&self.value);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !Userhash {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !Userhash {
        var self: Userhash = undefined;
        try reader.readNoEof(&self.value);
        return self;
    }

    pub fn deinit(self: *const Userhash, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const MessageIntegrity = struct {
    value: [20]u8,

    pub fn alignedSize(self: *const MessageIntegrity) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const MessageIntegrity) usize {
        return self.value.len;
    }

    pub fn serialize(self: *const MessageIntegrity, writer: anytype) !void {
        try writer.writeAll(&self.value);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !MessageIntegrity {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !MessageIntegrity {
        var self: MessageIntegrity = undefined;
        try reader.readNoEof(&self.value);
        return self;
    }

    pub fn deinit(self: *const MessageIntegrity, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const MessageIntegritySha256 = struct {
    storage: [32]u8,
    length: usize,

    pub fn fromRaw(value: []const u8) !MessageIntegritySha256 {
        if (!std.mem.isAligned(value.len, 4)) return error.InvalidAttributeFormat;
        var self: MessageIntegritySha256 = undefined;
        std.debug.assert(value.len <= @sizeOf(@TypeOf(self.storage)));
        std.mem.copy(u8, self.storage[0..value.len], value);
        self.length = value.len;
        return self;
    }

    pub fn alignedSize(self: *const MessageIntegritySha256) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const MessageIntegritySha256) usize {
        return self.length;
    }

    pub fn serialize(self: *const MessageIntegritySha256, writer: anytype) !void {
        std.debug.assert(std.mem.isAligned(self.length, 4));
        try writer.writeAll(self.storage[0..self.length]);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !MessageIntegritySha256 {
        _ = allocator;
        return MessageIntegritySha256.deserialize(reader, length);
    }

    pub fn deserialize(reader: anytype, length: usize) !MessageIntegritySha256 {
        var self: MessageIntegritySha256 = undefined;
        std.debug.assert(length <= @sizeOf(@TypeOf(self.storage)));
        try reader.readNoEof(self.storage[0..length]);
        self.length = length;
        return self;
    }

    pub fn deinit(self: *const MessageIntegritySha256, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const Fingerprint = struct {
    value: u32,

    pub fn alignedSize(self: *const Fingerprint) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const Fingerprint) usize {
        return @sizeOf(@TypeOf(self.value));
    }

    pub fn serialize(self: *const Fingerprint, writer: anytype) !void {
        try writer.writeIntBig(u32, self.value);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !Fingerprint {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !Fingerprint {
        const value = try reader.readIntBig(u32);
        return Fingerprint{ .value = value };
    }

    pub fn deinit(self: *const Fingerprint, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

fn rawErrorCodeFromClassAndNumber(class: u3, number: u8) u32 {
    var value: u32 = 0;
    value |= @intCast(u32, class) << 8;
    value |= @intCast(u32, number);

    return value;
}

pub const RawErrorCode = enum(u32) {
    try_alternate = rawErrorCodeFromClassAndNumber(3, 0),
    bad_request = rawErrorCodeFromClassAndNumber(4, 0),
    unauthenticated = rawErrorCodeFromClassAndNumber(4, 1),
    unknown_attribute = rawErrorCodeFromClassAndNumber(4, 20),
    stale_nonce = rawErrorCodeFromClassAndNumber(4, 38),
    server_error = rawErrorCodeFromClassAndNumber(5, 0),
};

pub const ErrorCode = struct {
    value: RawErrorCode,
    reason: []const u8,

    pub fn alignedSize(self: *const ErrorCode) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const ErrorCode) usize {
        return 4 + self.reason.len;
    }

    pub fn serialize(self: *const ErrorCode, writer: anytype) !void {
        try writer.writeIntBig(u32, @enumToInt(self.value));
        try io.writeAllAligned(self.reason, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !ErrorCode {
        const reason_length = length - @sizeOf(u32);
        var buffer = try allocator.alloc(u8, reason_length);
        errdefer allocator.free(buffer);

        return ErrorCode.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !ErrorCode {
        const raw_class_and_number = try reader.readIntBig(u32);
        const value = std.meta.intToEnum(RawErrorCode, raw_class_and_number) catch return error.InvalidAttributeFormat;
        try io.readNoEofAligned(reader, 4, buf);
        return ErrorCode{
            .value = value,
            .reason = buf,
        };
    }

    pub fn deinit(self: *const ErrorCode, allocator: std.mem.Allocator) void {
        allocator.free(self.reason);
    }
};

pub const Realm = struct {
    value: []const u8,

    pub fn alignedSize(self: *const Realm) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const Realm) usize {
        return self.value.len;
    }

    pub fn serialize(self: *const Realm, writer: anytype) !void {
        try io.writeAllAligned(self.value, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !Realm {
        var buffer = try allocator.alloc(u8, length);
        errdefer allocator.free(buffer);

        return Realm.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !Realm {
        try io.readNoEofAligned(reader, 4, buf);
        return Realm{
            .value = buf,
        };
    }

    pub fn deinit(self: *const Realm, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub const Nonce = struct {
    value: []const u8,

    pub fn alignedSize(self: *const Nonce) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const Nonce) usize {
        return self.value.len;
    }

    pub fn serialize(self: *const Nonce, writer: anytype) !void {
        try io.writeAllAligned(self.value, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !Nonce {
        var buffer = try allocator.alloc(u8, length);
        errdefer allocator.free(buffer);

        return Nonce.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !Nonce {
        try io.readNoEofAligned(reader, 4, buf);
        return Nonce{
            .value = buf,
        };
    }

    pub fn deinit(self: *const Nonce, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub const AlgorithmType = enum(u16) {
    md5 = 0x0001,
    sha256 = 0x0002,
};

pub const Algorithm = union(AlgorithmType) {
    md5: void,
    sha256: void,

    pub fn parameterSize(self: *const Algorithm) usize {
        return switch (self.*) {
            inline else => |algorithm| @sizeOf(@TypeOf(algorithm)),
        };
    }

    pub fn serialize(self: *const Algorithm, writer: anytype) !void {
        switch (self.*) {
            inline else => {
                try writer.writeIntBig(u16, @enumToInt(self.*));
                try writer.writeIntBig(u16, @truncate(u16, self.parameterSize()));
            },
        }
    }

    pub fn deserializeAlloc(reader: anytype, allocator: std.mem.Allocator) !Algorithm {
        _ = allocator;
        const raw_algorithm_type = try reader.readIntBig(u16);
        const parameter_length = try reader.readIntBig(u16);
        _ = parameter_length;

        const algorithm_type = std.meta.intToEnum(AlgorithmType, raw_algorithm_type) catch return error.InvalidAttributeFormat;
        switch (algorithm_type) {
            inline else => |tag| {
                if (tag != .md5 and tag != .sha256) @panic(@tagName(tag) ++ " algorithm is not implemented");
                try io.readNoEofAligned(reader, 4, &.{});
                return @unionInit(Algorithm, @tagName(tag), {});
            },
        }
    }

    pub fn deinit(self: *const Algorithm, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const PasswordAlgorithms = struct {
    algorithms: []Algorithm,

    pub fn alignedSize(self: *const PasswordAlgorithms) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const PasswordAlgorithms) usize {
        var raw_size: usize = 0;
        for (self.algorithms) |algorithm| {
            raw_size += 4 + std.mem.alignForward(algorithm.parameterSize(), 4);
        }
        return raw_size;
    }

    pub fn serialize(self: *const PasswordAlgorithms, writer: anytype) !void {
        for (self.algorithms) |algorithm| {
            try algorithm.serialize(writer);
        }
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !PasswordAlgorithms {
        var algorithm_list = try std.ArrayList(Algorithm).initCapacity(allocator, std.meta.fields(AlgorithmType).len);
        defer algorithm_list.deinit();
        var counting_stream = std.io.countingReader(reader);
        var counting_reader = counting_stream.reader();

        while (counting_stream.bytes_read < length) {
            try algorithm_list.append(try Algorithm.deserializeAlloc(counting_reader, allocator));
        }
        return PasswordAlgorithms{ .algorithms = algorithm_list.toOwnedSlice() };
    }

    pub fn deserialize(reader: anytype) !PasswordAlgorithms {
        _ = reader;
        return error.NotImplemented;
    }

    pub fn deinit(self: *const PasswordAlgorithms, allocator: std.mem.Allocator) void {
        for (self.algorithms) |a| {
            a.deinit(allocator);
        }
        allocator.free(self.algorithms);
    }
};

pub const PasswordAlgorithm = struct {
    algorithm: Algorithm,

    pub fn alignedSize(self: *const PasswordAlgorithm) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const PasswordAlgorithm) usize {
        return 4 + std.mem.alignForward(self.algorithm.parameterSize(), 4);
    }

    pub fn serialize(self: *const PasswordAlgorithm, writer: anytype) !void {
        try self.algorithm.serialize(writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !PasswordAlgorithm {
        _ = length;
        const algorithm = try Algorithm.deserializeAlloc(reader, allocator);
        return PasswordAlgorithm{ .algorithm = algorithm };
    }

    pub fn deserialize(reader: anytype) !PasswordAlgorithm {
        _ = reader;
        return error.NotImplemented;
    }

    pub fn deinit(self: *const PasswordAlgorithm, allocator: std.mem.Allocator) void {
        self.algorithm.deinit(allocator);
    }
};

pub const UnknownAttributes = struct {
    attribute_types: []u16,

    pub fn alignedSize(self: *const UnknownAttributes) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const UnknownAttributes) usize {
        return self.attribute_types.len * @sizeOf(u16);
    }

    pub fn serialize(self: *const UnknownAttributes, writer: anytype) !void {
        for (self.attribute_types) |attribute_type| {
            try writer.writeIntBig(u16, attribute_type);
        }
        if (self.attribute_types.len % 2 == 1) {
            try writer.writeIntBig(u16, 0);
        }
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !UnknownAttributes {
        if (length % 2 != 0) return error.InvalidAttributeFormat;
        var buffer = try allocator.alloc(u16, length / 2);
        errdefer allocator.free(buffer);

        return UnknownAttributes.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, attribute_types: []u16) !UnknownAttributes {
        for (attribute_types) |*attribute_type| {
            attribute_type.* = try reader.readIntBig(u16);
        }
        if (attribute_types.len % 2 == 1) {
            _ = try reader.readIntBig(u16);
        }
        return UnknownAttributes{ .attribute_types = attribute_types };
    }

    pub fn deinit(self: *const UnknownAttributes, allocator: std.mem.Allocator) void {
        allocator.free(self.attribute_types);
    }
};

pub const Software = struct {
    value: []const u8,

    pub fn alignedSize(self: *const Software) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const Software) usize {
        return self.value.len;
    }

    pub fn serialize(self: *const Software, writer: anytype) !void {
        try io.writeAllAligned(self.value, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !Software {
        var buffer = try allocator.alloc(u8, length);
        errdefer allocator.free(buffer);

        return Software.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !Software {
        try io.readNoEofAligned(reader, 4, buf);
        return Software{
            .value = buf,
        };
    }

    pub fn deinit(self: *const Software, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

pub const AlternateServer = struct {
    family: AddressFamily,
    port: u16,

    pub fn alignedSize(self: *const AlternateServer) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const AlternateServer) usize {
        return 4 + self.family.size();
    }

    pub fn serialize(self: *const AlternateServer, writer: anytype) !void {
        try writer.writeByte(0);
        switch (self.family) {
            inline else => |address, family| {
                try writer.writeByte(@enumToInt(family));
                try writer.writeIntBig(u16, self.port);
                try writer.writeIntBig(@TypeOf(address), address);
            },
        }
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !AlternateServer {
        _ = allocator;
        _ = length;
        return deserialize(reader);
    }

    pub fn deserialize(reader: anytype) !AlternateServer {
        if (try reader.readByte() != 0x00) return error.InvalidAttributeFormat;
        const raw_family_type = try reader.readByte();
        const family_type = std.meta.intToEnum(AddressFamilyType, raw_family_type) catch return error.InvalidAttributeFormat;
        const port = try reader.readIntBig(u16);

        const family = switch (family_type) {
            .ipv4 => AddressFamily{ .ipv4 = try reader.readIntBig(u32) },
            .ipv6 => AddressFamily{ .ipv6 = try reader.readIntBig(u128) },
        };

        return AlternateServer{
            .family = family,
            .port = port,
        };
    }

    pub fn deinit(self: *const AlternateServer, allocator: std.mem.Allocator) void {
        _ = allocator;
        _ = self;
    }
};

pub const AlternateDomain = struct {
    value: []const u8,

    pub fn alignedSize(self: *const AlternateDomain) usize {
        return std.mem.alignForward(self.size(), 4);
    }

    pub fn size(self: *const AlternateDomain) usize {
        return self.value.len;
    }

    pub fn serialize(self: *const AlternateDomain, writer: anytype) !void {
        try io.writeAllAligned(self.value, 4, writer);
    }

    pub fn deserializeAlloc(reader: anytype, length: usize, allocator: std.mem.Allocator) !AlternateDomain {
        var buffer = try allocator.alloc(u8, length);
        errdefer allocator.free(buffer);

        return AlternateDomain.deserialize(reader, buffer);
    }

    pub fn deserialize(reader: anytype, buf: []u8) !AlternateDomain {
        try io.readNoEofAligned(reader, 4, buf);
        return AlternateDomain{
            .value = buf,
        };
    }

    pub fn deinit(self: *const AlternateDomain, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

test {
    _ = @import("attributes/test.zig");
}
