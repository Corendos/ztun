// Copyright 2022 - Corentin Godeau and the ztun contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const io = @import("io.zig");

const magic_cookie = @import("constants.zig").magic_cookie;

/// Represents a raw STUN attribute.
pub const Attribute = struct {
    /// Stores the type of message.
    type: u16,
    /// Stores the body of the attribute.
    data: []const u8,

    /// Computes the attribute length in a message (padded to a 4 bytes boundary).
    pub fn length(self: Attribute) usize {
        return 4 + std.mem.alignForward(usize, self.data.len, 4);
    }
};

/// Common types of stun attributes.
pub const Type = struct {
    // RFC 8489
    pub const mapped_address = 0x0001;
    pub const xor_mapped_address = 0x0020;
    pub const username = 0x0006;
    pub const userhash = 0x001E;
    pub const message_integrity = 0x0008;
    pub const message_integrity_sha256 = 0x001C;
    pub const fingerprint = 0x8028;
    pub const error_code = 0x0009;
    pub const realm = 0x0014;
    pub const nonce = 0x0015;
    pub const password_algorithms = 0x8002;
    pub const password_algorithm = 0x001D;
    pub const unknown_attributes = 0x000A;
    pub const software = 0x8022;
    pub const alternate_server = 0x8023;
    pub const alternate_domain = 0x8003;

    // RFC 8445
    pub const priority = 0x0024;
    pub const use_candidate = 0x0025;
    pub const ice_controlled = 0x8029;
    pub const ice_controlling = 0x802A;
};

/// Returns true if the attribute type is a "Comprehension Required" attribute.
pub inline fn isComprehensionRequired(value: u16) bool {
    return 0x000 <= value and value < 0x8000;
}

/// Returns true if the attribute type is a "Comprehension optional" attribute.
pub inline fn isComprehensionOptional(value: u16) bool {
    return !isComprehensionRequired(value);
}

/// Writes an attribute to the given writer.
pub fn write(attribute: Attribute, writer: anytype) !void {
    try writer.writeIntBig(u16, attribute.type);
    try writer.writeIntBig(u16, @intCast(u16, attribute.data.len));
    try io.writeAllAligned(attribute.data, 4, writer);
}

/// Reads an attribute from the given reader and allocate the required storage using the given allocator.
/// The attribute owns the allocated memory.
pub fn readAlloc(reader: anytype, allocator: std.mem.Allocator) !Attribute {
    const @"type" = try reader.readIntBig(u16);
    const len = try reader.readIntBig(u16);
    var data = try allocator.alloc(u8, len);
    errdefer allocator.free(data);

    try io.readNoEofAligned(reader, 4, data);
    return Attribute{ .type = @"type", .data = data };
}

test "write attribute" {
    const attribute = Attribute{
        .type = 0x0042,
        .data = &[_]u8{ 1, 2, 3 },
    };

    var buffer: [128]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    try write(attribute, stream.writer());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x42, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00 }, stream.getWritten());
}

test "read attribute" {
    const raw = [_]u8{ 0x00, 0x42, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00 };

    var stream = std.io.fixedBufferStream(&raw);

    const attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);
    try std.testing.expectEqual(@as(u16, 0x042), attribute.type);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, attribute.data);
}

/// Namespace containing the common attribute as typed struct.
/// The following struct all have a "toAttribute" and a "fromAttribute" method to convert to/from raw attribute.
/// Some conversions require an allocator to allocate the necessary storage. In that case, the struct owns the memory.
pub const common = struct {
    pub const ConversionError = error{
        InvalidAttribute,
        NoSpaceLeft,
        EndOfStream,
    } || std.mem.Allocator.Error;

    pub const AddressFamilyType = enum(u8) {
        ipv4 = 0x01,
        ipv6 = 0x02,
    };

    pub const AddressFamily = union(AddressFamilyType) {
        ipv4: u32,
        ipv6: u128,
        pub fn format(self: AddressFamily, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            switch (self) {
                .ipv4 => |value| {
                    const endian_corrected_value = std.mem.nativeToBig(u32, value);
                    var bytes = std.mem.asBytes(&endian_corrected_value);
                    try writer.print("{}.{}.{}.{}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
                },
                .ipv6 => |value| {
                    const endian_corrected_value = std.mem.nativeToBig(u128, value);
                    var bytes = std.mem.asBytes(&endian_corrected_value);
                    try writer.print("{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                        bytes[0],  bytes[1],
                        bytes[2],  bytes[3],
                        bytes[4],  bytes[5],
                        bytes[6],  bytes[7],
                        bytes[8],  bytes[9],
                        bytes[10], bytes[11],
                        bytes[12], bytes[13],
                        bytes[14], bytes[15],
                    });
                },
            }
            _ = options;
            _ = fmt;
        }
    };

    /// Represents the MAPPED-ADDRESS attribute.
    pub const MappedAddress = struct {
        family: AddressFamily,
        port: u16,

        pub fn fromAttribute(attribute: Attribute) ConversionError!MappedAddress {
            if (attribute.type != Type.mapped_address) return error.InvalidAttribute;

            var stream = std.io.fixedBufferStream(attribute.data);
            var reader = stream.reader();
            _ = try reader.readByte();
            const raw_family_type = reader.readByte() catch return error.InvalidAttribute;
            const family_type = std.meta.intToEnum(AddressFamilyType, raw_family_type) catch return error.InvalidAttribute;
            const port: u16 = reader.readIntBig(u16) catch return error.InvalidAttribute;
            switch (family_type) {
                .ipv4 => {
                    const raw_address = reader.readIntBig(u32) catch return error.InvalidAttribute;
                    return MappedAddress{ .family = .{ .ipv4 = raw_address }, .port = port };
                },
                .ipv6 => {
                    const raw_address = reader.readIntBig(u128) catch return error.InvalidAttribute;
                    return MappedAddress{ .family = .{ .ipv6 = raw_address }, .port = port };
                },
            }
        }

        pub fn toAttribute(self: MappedAddress, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            const data_size = 4 + @as(usize, switch (self.family) {
                .ipv4 => 4,
                .ipv6 => 16,
            });
            var data = try allocator.alloc(u8, data_size);
            errdefer allocator.free(data);

            var stream = std.io.fixedBufferStream(data);
            var writer = stream.writer();
            writer.writeByte(0) catch unreachable;
            writer.writeByte(@enumToInt(self.family)) catch unreachable;
            writer.writeIntBig(u16, self.port) catch unreachable;
            switch (self.family) {
                .ipv4 => |value| writer.writeIntBig(u32, value) catch unreachable,
                .ipv6 => |value| writer.writeIntBig(u128, value) catch unreachable,
            }

            return Attribute{ .type = Type.mapped_address, .data = data };
        }
    };

    /// Represents the XOR-MAPPED-ADDRESS attribute.
    pub const XorMappedAddress = struct {
        x_family: AddressFamily,
        x_port: u16,

        pub fn fromAttribute(attribute: Attribute) ConversionError!XorMappedAddress {
            if (attribute.type != Type.xor_mapped_address) return error.InvalidAttribute;

            var stream = std.io.fixedBufferStream(attribute.data);
            var reader = stream.reader();
            _ = try reader.readByte();
            const raw_x_family_type = reader.readByte() catch return error.InvalidAttribute;
            const x_family_type = std.meta.intToEnum(AddressFamilyType, raw_x_family_type) catch return error.InvalidAttribute;
            const x_port: u16 = reader.readIntBig(u16) catch return error.InvalidAttribute;
            switch (x_family_type) {
                .ipv4 => {
                    const raw_address = reader.readIntBig(u32) catch return error.InvalidAttribute;
                    return XorMappedAddress{ .x_family = .{ .ipv4 = raw_address }, .x_port = x_port };
                },
                .ipv6 => {
                    const raw_address = reader.readIntBig(u128) catch return error.InvalidAttribute;
                    return XorMappedAddress{ .x_family = .{ .ipv6 = raw_address }, .x_port = x_port };
                },
            }
        }

        pub fn toAttribute(self: XorMappedAddress, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            const data_size = 4 + @as(usize, switch (self.x_family) {
                .ipv4 => 4,
                .ipv6 => 16,
            });
            var data = try allocator.alloc(u8, data_size);
            errdefer allocator.free(data);

            var stream = std.io.fixedBufferStream(data);
            var writer = stream.writer();
            writer.writeByte(0) catch unreachable;
            writer.writeByte(@enumToInt(self.x_family)) catch unreachable;
            writer.writeIntBig(u16, self.x_port) catch unreachable;
            switch (self.x_family) {
                .ipv4 => |value| writer.writeIntBig(u32, value) catch unreachable,
                .ipv6 => |value| writer.writeIntBig(u128, value) catch unreachable,
            }

            return Attribute{ .type = Type.xor_mapped_address, .data = data };
        }
    };

    /// Encodes a MappedAddress to the corresponding XorMappedAddress.
    pub fn encode(mapped_address: MappedAddress, transaction_id: u96) XorMappedAddress {
        const x_port = mapped_address.port ^ @truncate(u16, (magic_cookie & 0xFFFF0000) >> 16);

        const x_family = switch (mapped_address.family) {
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

    /// Decodes a MappedAddress from the corresponding XorMappedAddress.
    pub fn decode(xor_mapped_address: XorMappedAddress, transaction_id: u96) MappedAddress {
        const port = xor_mapped_address.x_port ^ @truncate(u16, (magic_cookie & 0xFFFF0000) >> 16);

        const family = switch (xor_mapped_address.x_family) {
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

    /// Represents the USERNAME attribute.
    pub const Username = struct {
        value: []const u8,

        pub fn fromAttribute(attribute: Attribute) ConversionError!Username {
            if (attribute.type != Type.username) return error.InvalidAttribute;

            return Username{ .value = attribute.data };
        }

        pub fn toAttribute(self: Username, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            return Attribute{ .type = Type.username, .data = try allocator.dupe(u8, self.value) };
        }
    };

    /// Represents the USERHASH attribute.
    pub const Userhash = struct {
        value: [32]u8,

        pub fn fromAttribute(attribute: Attribute) ConversionError!Userhash {
            if (attribute.type != Type.userhash) return error.InvalidAttribute;
            if (attribute.data.len != 32) return error.InvalidAttribute;
            var self: Userhash = undefined;
            std.mem.copy(u8, &self.value, attribute.data);
            return self;
        }

        pub fn toAttribute(self: Userhash, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            var data = try allocator.alloc(u8, self.value.len);
            errdefer allocator.free(data);

            std.mem.copy(u8, data, &self.value);

            return Attribute{ .type = Type.userhash, .data = data };
        }
    };

    /// Represents the MESSAGE-INTEGRITY attribute.
    pub const MessageIntegrity = struct {
        value: [20]u8,

        pub fn fromAttribute(attribute: Attribute) ConversionError!MessageIntegrity {
            if (attribute.type != Type.message_integrity) return error.InvalidAttribute;
            if (attribute.data.len != 20) return error.InvalidAttribute;
            var self: MessageIntegrity = undefined;
            std.mem.copy(u8, &self.value, attribute.data);
            return self;
        }

        pub fn toAttribute(self: MessageIntegrity, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            var data = try allocator.alloc(u8, self.value.len);
            errdefer allocator.free(data);

            std.mem.copy(u8, data, &self.value);

            return Attribute{ .type = Type.message_integrity, .data = data };
        }
    };

    /// Represents the MESSAGE-INTEGRITY-SHA256 attribute.
    pub const MessageIntegritySha256 = struct {
        storage: [32]u8,
        length: usize,

        pub fn fromAttribute(attribute: Attribute) ConversionError!MessageIntegritySha256 {
            if (attribute.type != Type.message_integrity_sha256) return error.InvalidAttribute;
            if (attribute.data.len > 32) return error.InvalidAttribute;
            var self = MessageIntegritySha256{
                .storage = undefined,
                .length = attribute.data.len,
            };
            std.mem.copy(u8, self.storage[0..attribute.data.len], attribute.data);
            return self;
        }

        pub fn toAttribute(self: MessageIntegritySha256, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            var data = try allocator.alloc(u8, self.length);
            errdefer allocator.free(data);

            std.mem.copy(u8, data, self.storage[0..self.length]);

            return Attribute{ .type = Type.message_integrity_sha256, .data = data };
        }
    };

    /// Represents the FINGERPRINT attribute.
    pub const Fingerprint = struct {
        value: u32,

        pub fn fromAttribute(attribute: Attribute) ConversionError!Fingerprint {
            if (attribute.type != Type.fingerprint) return error.InvalidAttribute;
            var stream = std.io.fixedBufferStream(attribute.data);
            var reader = stream.reader();

            var value = reader.readIntBig(u32) catch return error.InvalidAttribute;
            return Fingerprint{
                .value = value,
            };
        }

        pub fn toAttribute(self: Fingerprint, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            var data = try allocator.alloc(u8, 4);
            errdefer allocator.free(data);

            var stream = std.io.fixedBufferStream(data);
            var writer = stream.writer();

            writer.writeIntBig(u32, self.value) catch unreachable;

            return Attribute{ .type = Type.fingerprint, .data = data };
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

        pub inline fn class(self: RawErrorCode) u3 {
            return @intCast(u3, (@as(u32, @enumToInt(self)) & 0b11100000000) >> 8);
        }

        pub inline fn number(self: RawErrorCode) u8 {
            return @intCast(u8, @as(u32, @enumToInt(self)) & 0xFF);
        }
    };

    /// Represents the ERROR-CODE attribute.
    pub const ErrorCode = struct {
        value: RawErrorCode,
        reason: []const u8,

        pub fn fromAttribute(attribute: Attribute) ConversionError!ErrorCode {
            if (attribute.type != Type.error_code) return error.InvalidAttribute;
            var stream = std.io.fixedBufferStream(attribute.data);
            var reader = stream.reader();

            _ = reader.readIntBig(u16) catch return error.InvalidAttribute;
            const raw_class = reader.readByte() catch return error.InvalidAttribute;
            const raw_number = reader.readByte() catch return error.InvalidAttribute;
            const raw_error_code = std.meta.intToEnum(RawErrorCode, rawErrorCodeFromClassAndNumber(@intCast(u3, raw_class), raw_number)) catch return error.InvalidAttribute;

            const reason = stream.buffer[stream.pos..];

            return ErrorCode{ .value = raw_error_code, .reason = reason };
        }

        pub fn toAttribute(self: ErrorCode, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            var data = try allocator.alloc(u8, 4 + self.reason.len);
            errdefer allocator.free(data);

            var stream = std.io.fixedBufferStream(data);
            var writer = stream.writer();

            writer.writeIntBig(u32, @enumToInt(self.value)) catch unreachable;
            writer.writeAll(self.reason) catch unreachable;

            return Attribute{ .type = Type.error_code, .data = data };
        }
    };

    /// Represents the REALM attribute.
    pub const Realm = struct {
        value: []const u8,

        pub fn fromAttribute(attribute: Attribute) ConversionError!Realm {
            if (attribute.type != Type.realm) return error.InvalidAttribute;

            return Realm{ .value = attribute.data };
        }

        pub fn toAttribute(self: Realm, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            return Attribute{ .type = Type.realm, .data = try allocator.dupe(u8, self.value) };
        }
    };

    /// Represents the NONCE attribute.
    pub const Nonce = struct {
        value: []const u8,

        pub fn fromAttribute(attribute: Attribute) ConversionError!Nonce {
            if (attribute.type != Type.nonce) return error.InvalidAttribute;

            return Nonce{ .value = attribute.data };
        }

        pub fn toAttribute(self: Nonce, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            return Attribute{ .type = Type.nonce, .data = try allocator.dupe(u8, self.value) };
        }
    };

    pub const AlgorithmType = struct {
        pub const md5 = 0x0001;
        pub const sha256 = 0x0002;
    };

    pub const Algorithm = struct {
        type: u16,
        parameters: []const u8,
    };

    /// Represents the PASSWORD-ALGORITHMS attribute.
    pub const PasswordAlgorithms = struct {
        algorithms: []Algorithm,

        pub fn fromAttribute(attribute: Attribute, allocator: std.mem.Allocator) ConversionError!PasswordAlgorithms {
            if (attribute.type != Type.password_algorithms) return error.InvalidAttribute;

            var stream = std.io.fixedBufferStream(attribute.data);
            var reader = stream.reader();

            var algorithms_count: usize = 0;
            while (stream.pos < stream.buffer.len) : (algorithms_count += 1) {
                _ = reader.readIntBig(u16) catch return error.InvalidAttribute;
                const length = reader.readIntBig(u16) catch return error.InvalidAttribute;
                const aligned_length = std.mem.alignForward(usize, length, 4);
                reader.skipBytes(aligned_length, .{}) catch return error.InvalidAttribute;
            }

            var algorithms = try allocator.alloc(Algorithm, algorithms_count);
            errdefer allocator.free(algorithms);

            stream.reset();
            for (algorithms) |*algorithm| {
                const @"type" = reader.readIntBig(u16) catch return error.InvalidAttribute;
                const length = reader.readIntBig(u16) catch return error.InvalidAttribute;
                const aligned_length = std.mem.alignForward(usize, length, 4);
                algorithm.type = @"type";
                algorithm.parameters = stream.buffer[stream.pos .. stream.pos + length];
                reader.skipBytes(aligned_length, .{}) catch return error.InvalidAttribute;
            }

            return PasswordAlgorithms{ .algorithms = algorithms };
        }

        pub fn toAttribute(self: PasswordAlgorithms, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            var data_size: usize = 0;
            for (self.algorithms) |algorithm| {
                data_size += 4 + std.mem.alignForward(usize, algorithm.parameters.len, 4);
            }
            var data = try allocator.alloc(u8, data_size);
            errdefer allocator.free(data);

            var stream = std.io.fixedBufferStream(data);
            var writer = stream.writer();

            for (self.algorithms) |algorithm| {
                writer.writeIntBig(u16, algorithm.type) catch unreachable;
                writer.writeIntBig(u16, @intCast(u16, algorithm.parameters.len)) catch unreachable;
                io.writeAllAligned(algorithm.parameters, 4, writer) catch unreachable;
            }

            return Attribute{ .type = Type.password_algorithms, .data = data };
        }
    };

    /// Represents the PASSWORD-ALGORITHM attribute.
    pub const PasswordAlgorithm = struct {
        algorithm: Algorithm,

        pub fn fromAttribute(attribute: Attribute) ConversionError!PasswordAlgorithm {
            if (attribute.type != Type.password_algorithm) return error.InvalidAttribute;

            var stream = std.io.fixedBufferStream(attribute.data);
            var reader = stream.reader();

            const @"type" = reader.readIntBig(u16) catch return error.InvalidAttribute;
            const length = reader.readIntBig(u16) catch return error.InvalidAttribute;
            const aligned_length = std.mem.alignForward(usize, length, 4);
            const algorithm = Algorithm{
                .type = @"type",
                .parameters = stream.buffer[stream.pos .. stream.pos + length],
            };
            reader.skipBytes(aligned_length, .{}) catch return error.InvalidAttribute;

            return PasswordAlgorithm{ .algorithm = algorithm };
        }

        pub fn toAttribute(self: PasswordAlgorithm, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            var data = try allocator.alloc(u8, 4 + std.mem.alignForward(usize, self.algorithm.parameters.len, 4));
            errdefer allocator.free(data);

            var stream = std.io.fixedBufferStream(data);
            var writer = stream.writer();

            writer.writeIntBig(u16, self.algorithm.type) catch unreachable;
            writer.writeIntBig(u16, @intCast(u16, self.algorithm.parameters.len)) catch unreachable;
            io.writeAllAligned(self.algorithm.parameters, 4, writer) catch unreachable;

            return Attribute{ .type = Type.password_algorithm, .data = data };
        }
    };

    /// Represents the UNKNOWN-ATTRIBUTEs attribute.
    pub const UnknownAttributes = struct {
        attribute_types: []u16,

        pub fn fromAttribute(attribute: Attribute, allocator: std.mem.Allocator) ConversionError!UnknownAttributes {
            if (attribute.type != Type.unknown_attributes) return error.InvalidAttribute;

            var attribute_types = try allocator.alloc(u16, attribute.data.len / 2);
            errdefer allocator.free(attribute_types);

            var stream = std.io.fixedBufferStream(attribute.data);
            var reader = stream.reader();

            for (attribute_types) |*attribute_type| {
                attribute_type.* = reader.readIntBig(u16) catch return error.InvalidAttribute;
            }

            return UnknownAttributes{ .attribute_types = attribute_types };
        }

        pub fn toAttribute(self: UnknownAttributes, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            var data = try allocator.alloc(u8, self.attribute_types.len * 2);
            errdefer allocator.free(data);

            var stream = std.io.fixedBufferStream(data);
            var writer = stream.writer();

            for (self.attribute_types) |attribute_type| {
                writer.writeIntBig(u16, attribute_type) catch unreachable;
            }

            return Attribute{ .type = Type.unknown_attributes, .data = data };
        }
    };

    /// Represents the SOFTWARE attribute.
    pub const Software = struct {
        value: []const u8,

        pub fn fromAttribute(attribute: Attribute) ConversionError!Software {
            if (attribute.type != Type.software) return error.InvalidAttribute;

            return Software{ .value = attribute.data };
        }

        pub fn toAttribute(self: Software, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            return Attribute{ .type = Type.software, .data = try allocator.dupe(u8, self.value) };
        }
    };

    /// Represents the ALTERNATE-SERVER attribute.
    pub const AlternateServer = struct {
        family: AddressFamily,
        port: u16,

        pub fn fromAttribute(attribute: Attribute) ConversionError!AlternateServer {
            if (attribute.type != Type.alternate_server) return error.InvalidAttribute;

            var stream = std.io.fixedBufferStream(attribute.data);
            var reader = stream.reader();
            _ = try reader.readByte();
            const raw_family_type = reader.readByte() catch return error.InvalidAttribute;
            const family_type = std.meta.intToEnum(AddressFamilyType, raw_family_type) catch return error.InvalidAttribute;
            const port: u16 = reader.readIntBig(u16) catch return error.InvalidAttribute;
            switch (family_type) {
                .ipv4 => {
                    const raw_address = reader.readIntBig(u32) catch return error.InvalidAttribute;
                    return AlternateServer{ .family = .{ .ipv4 = raw_address }, .port = port };
                },
                .ipv6 => {
                    const raw_address = reader.readIntBig(u128) catch return error.InvalidAttribute;
                    return AlternateServer{ .family = .{ .ipv6 = raw_address }, .port = port };
                },
            }
        }

        pub fn toAttribute(self: AlternateServer, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            const data_size = 4 + @as(usize, switch (self.family) {
                .ipv4 => 4,
                .ipv6 => 16,
            });
            var data = try allocator.alloc(u8, data_size);
            errdefer allocator.free(data);

            var stream = std.io.fixedBufferStream(data);
            var writer = stream.writer();
            writer.writeByte(0) catch unreachable;
            writer.writeByte(@enumToInt(self.family)) catch unreachable;
            writer.writeIntBig(u16, self.port) catch unreachable;
            switch (self.family) {
                .ipv4 => |value| writer.writeIntBig(u32, value) catch unreachable,
                .ipv6 => |value| writer.writeIntBig(u128, value) catch unreachable,
            }

            return Attribute{ .type = Type.alternate_server, .data = data };
        }
    };

    /// Represents the ALTERNATE-DOMAIN attribute.
    pub const AlternateDomain = struct {
        value: []const u8,

        pub fn fromAttribute(attribute: Attribute) ConversionError!AlternateDomain {
            if (attribute.type != Type.alternate_domain) return error.InvalidAttribute;

            return AlternateDomain{ .value = attribute.data };
        }

        pub fn toAttribute(self: AlternateDomain, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            return Attribute{ .type = Type.alternate_domain, .data = try allocator.dupe(u8, self.value) };
        }
    };

    /// Represents the PRIORITY attribute.
    pub const Priority = struct {
        value: u32,

        pub fn fromAttribute(attribute: Attribute) ConversionError!Priority {
            if (attribute.type != Type.priority) return error.InvalidAttribute;

            var stream = std.io.fixedBufferStream(attribute.data);
            var reader = stream.reader();
            const value = reader.readIntBig(u32) catch return error.InvalidAttribute;
            return Priority{ .value = value };
        }

        pub fn toAttribute(self: Priority, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            var data = try allocator.alloc(u8, 4);
            errdefer allocator.free(data);

            var stream = std.io.fixedBufferStream(data);
            var writer = stream.writer();
            writer.writeIntBig(u32, self.value) catch unreachable;

            return Attribute{ .type = Type.priority, .data = data };
        }
    };

    /// Represents the USE-CANDIDATE attribute.
    pub const UseCandidate = struct {
        pub fn fromAttribute(attribute: Attribute) ConversionError!UseCandidate {
            if (attribute.type != Type.use_candidate) return error.InvalidAttribute;
            return UseCandidate{};
        }

        pub fn toAttribute(self: UseCandidate, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            _ = allocator;
            _ = self;
            return Attribute{ .type = Type.use_candidate, .data = &.{} };
        }
    };

    /// Represents the ICE-CONTROLLED attribute.
    pub const IceControlled = struct {
        value: u64,

        pub fn fromAttribute(attribute: Attribute) ConversionError!IceControlled {
            if (attribute.type != Type.ice_controlled) return error.InvalidAttribute;

            var stream = std.io.fixedBufferStream(attribute.data);
            var reader = stream.reader();
            const value = reader.readIntBig(u64) catch return error.InvalidAttribute;
            return IceControlled{ .value = value };
        }

        pub fn toAttribute(self: IceControlled, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            var data = try allocator.alloc(u8, 8);
            errdefer allocator.free(data);

            var stream = std.io.fixedBufferStream(data);
            var writer = stream.writer();
            writer.writeIntBig(u64, self.value) catch unreachable;

            return Attribute{ .type = Type.ice_controlled, .data = data };
        }
    };

    /// Represents the ICE-CONTROLLING attribute.
    pub const IceControlling = struct {
        value: u64,

        pub fn fromAttribute(attribute: Attribute) ConversionError!IceControlling {
            if (attribute.type != Type.ice_controlling) return error.InvalidAttribute;

            var stream = std.io.fixedBufferStream(attribute.data);
            var reader = stream.reader();
            const value = reader.readIntBig(u64) catch return error.InvalidAttribute;
            return IceControlling{ .value = value };
        }

        pub fn toAttribute(self: IceControlling, allocator: std.mem.Allocator) error{OutOfMemory}!Attribute {
            var data = try allocator.alloc(u8, 8);
            errdefer allocator.free(data);

            var stream = std.io.fixedBufferStream(data);
            var writer = stream.writer();
            writer.writeIntBig(u64, self.value) catch unreachable;

            return Attribute{ .type = Type.ice_controlling, .data = data };
        }
    };
};

test "MAPPED-ADDRESS deserialization" {
    const buffer = [_]u8{
        // Header
        0x00, 0x01,
        0x00, 0x08,
        // Padding
        0x00,
        // Family type
        0x01,
        // Port
        0x01, 0x02,
        // Address
        127,  0,
        0,    1,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    var mapped_address_attribute = try common.MappedAddress.fromAttribute(attribute);

    try std.testing.expectEqual(@as(u16, 0x0102), mapped_address_attribute.port);
    try std.testing.expectEqual(common.AddressFamilyType.ipv4, mapped_address_attribute.family);
    try std.testing.expectEqual(@as(u32, 0x7F000001), mapped_address_attribute.family.ipv4);
}

test "XOR-MAPPED-ADDRESS deserialization" {
    const buffer = [_]u8{
        // Header
        0x00, 0x20,
        0x00, 0x08,
        // Padding
        0x00,
        // Family type
        0x01,
        // X-Port
        0x20, 0x10,
        // X-Address
        0x5E, 0x12,
        0xA4, 0x43,
    };

    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    var xor_mapped_address_attribute = try common.XorMappedAddress.fromAttribute(attribute);

    try std.testing.expectEqual(@as(u16, 0x2010), xor_mapped_address_attribute.x_port);
    try std.testing.expectEqual(common.AddressFamilyType.ipv4, xor_mapped_address_attribute.x_family);
    try std.testing.expectEqual(@as(u32, 0x5E12A443), xor_mapped_address_attribute.x_family.ipv4);

    const decoded_attribute = common.decode(xor_mapped_address_attribute, 0x0);
    try std.testing.expectEqual(@as(u16, 0x0102), decoded_attribute.port);
    try std.testing.expectEqual(common.AddressFamilyType.ipv4, decoded_attribute.family);
    try std.testing.expectEqual(@as(u32, 0x7F000001), decoded_attribute.family.ipv4);
}

test "USERNAME deserialization" {
    const buffer = [_]u8{
        // Header
        0x00,
        0x06,
        0x00,
        0x04,
        // Value
        @as(u8, 'z'),
        @as(u8, 't'),
        @as(u8, 'u'),
        @as(u8, 'n'),
    };

    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    var username_attribute = try common.Username.fromAttribute(attribute);

    try std.testing.expectEqualStrings("ztun", username_attribute.value);
}

test "USERHASH deserialization" {
    const buffer = [_]u8{
        // Header
        0x00,
        0x1E,
        0x00,
        0x20,
        // Value
        @as(u8, 'a'),
        @as(u8, 'b'),
        @as(u8, 'c'),
        @as(u8, 'd'),
        @as(u8, 'e'),
        @as(u8, 'f'),
        @as(u8, 'g'),
        @as(u8, 'h'),
        @as(u8, 'i'),
        @as(u8, 'j'),
        @as(u8, 'k'),
        @as(u8, 'l'),
        @as(u8, 'm'),
        @as(u8, 'n'),
        @as(u8, 'o'),
        @as(u8, 'p'),
        @as(u8, 'q'),
        @as(u8, 'r'),
        @as(u8, 's'),
        @as(u8, 't'),
        @as(u8, 'u'),
        @as(u8, 'v'),
        @as(u8, 'w'),
        @as(u8, 'x'),
        @as(u8, 'y'),
        @as(u8, 'z'),
        @as(u8, 'a'),
        @as(u8, 'b'),
        @as(u8, 'c'),
        @as(u8, 'd'),
        @as(u8, 'e'),
        @as(u8, 'f'),
    };

    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    var userhash_attribute = try common.Userhash.fromAttribute(attribute);

    try std.testing.expectEqualStrings("abcdefghijklmnopqrstuvwxyzabcdef", &userhash_attribute.value);
}

// NOTE(Corentin): Hash is the SHA-1 of "ztun"

test "MESSAGE-INTEGRITY deserialization" {
    const hash = [_]u8{
        0x43,
        0x23,
        0xc5,
        0x7d,
        0x5d,
        0x67,
        0x74,
        0xac,
        0x3e,
        0xdb,
        0xcc,
        0x0a,
        0x1d,
        0x48,
        0xc2,
        0xd2,
        0x52,
        0x78,
        0x3e,
        0xa4,
    };

    const buffer = [_]u8{
        // Header
        0x00,
        0x08,
        0x00,
        0x14,
        // Value
        0x43,
        0x23,
        0xc5,
        0x7d,
        0x5d,
        0x67,
        0x74,
        0xac,
        0x3e,
        0xdb,
        0xcc,
        0x0a,
        0x1d,
        0x48,
        0xc2,
        0xd2,
        0x52,
        0x78,
        0x3e,
        0xa4,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const message_integrity_attribute = try common.MessageIntegrity.fromAttribute(attribute);

    try std.testing.expectEqualSlices(u8, &hash, &message_integrity_attribute.value);
}

// NOTE(Corentin): Hash is the 20 first bytes of SHA-256 of "ztun"
test "MESSAGE-INTEGRITY-SHA256 deserialization" {
    const hash = [_]u8{
        0x4d,
        0xff,
        0xed,
        0xda,
        0x21,
        0x1d,
        0x83,
        0x6d,
        0x26,
        0x12,
        0x92,
        0x2e,
        0x3d,
        0xa5,
        0x87,
        0x02,
        0x5d,
        0x18,
        0xee,
        0xec,
    };

    const buffer = [_]u8{
        // Header
        0x00,
        0x1C,
        0x00,
        0x14,
        // Value
        0x4d,
        0xff,
        0xed,
        0xda,
        0x21,
        0x1d,
        0x83,
        0x6d,
        0x26,
        0x12,
        0x92,
        0x2e,
        0x3d,
        0xa5,
        0x87,
        0x02,
        0x5d,
        0x18,
        0xee,
        0xec,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const message_integrity_sha256_attribute = try common.MessageIntegritySha256.fromAttribute(attribute);

    try std.testing.expectEqualSlices(u8, &hash, message_integrity_sha256_attribute.storage[0..message_integrity_sha256_attribute.length]);
}

test "FINGERPRINT deserialization" {
    const buffer = [_]u8{
        // Header
        0x80,
        0x28,
        0x00,
        0x04,
        // Value
        0x01,
        0x02,
        0x03,
        0x04,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const fingerprint_attribute = try common.Fingerprint.fromAttribute(attribute);

    try std.testing.expectEqual(@as(u32, 0x01020304), fingerprint_attribute.value);
}

test "ERROR-CODE deserialization" {
    const buffer = [_]u8{
        // Header
        0x00,
        0x09,
        0x00,
        0x0A,
        // Class and number
        0x00,
        0x00,
        4,
        20,
    } ++ "reason" ++ [_]u8{ 0, 0 };

    var stream = std.io.fixedBufferStream(buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const error_code_attribute = try common.ErrorCode.fromAttribute(attribute);

    try std.testing.expectEqual(common.RawErrorCode.unknown_attribute, error_code_attribute.value);
    try std.testing.expectEqualStrings("reason", error_code_attribute.reason);
}

test "REALM deserialization" {
    const buffer = [_]u8{
        // Header
        0x00,
        0x14,
        0x00,
        0x05,
        // Value
        @as(u8, 'r'),
        @as(u8, 'e'),
        @as(u8, 'a'),
        @as(u8, 'l'),
        @as(u8, 'm'),
        // Padding
        0,
        0,
        0,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const realm_attribute = try common.Realm.fromAttribute(attribute);

    try std.testing.expectEqualStrings("realm", realm_attribute.value);
}

test "NONCE deserialization" {
    const buffer = [_]u8{
        // Header
        0x00,
        0x15,
        0x00,
        0x05,
        // Value
        @as(u8, 'n'),
        @as(u8, 'o'),
        @as(u8, 'n'),
        @as(u8, 'c'),
        @as(u8, 'e'),
        // Padding
        0,
        0,
        0,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const nonce_attribute = try common.Nonce.fromAttribute(attribute);

    try std.testing.expectEqualStrings("nonce", nonce_attribute.value);
}

test "PASSWORD-ALGORITHMS deserialization" {
    const buffer = [_]u8{
        // Header
        0x80, 0x02,
        0x00, 0x08,
        // Type MD5
        0x00, 0x01,
        // Length
        0x00, 0x00,
        // Empty parameters
        // Type SHA256
        0x00, 0x02,
        // Length
        0x00,
        0x00,
        // Empty parameters
    };

    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const password_algorithms_attribute = try common.PasswordAlgorithms.fromAttribute(attribute, std.testing.allocator);
    defer std.testing.allocator.free(password_algorithms_attribute.algorithms);

    try std.testing.expectEqual(@as(usize, 2), password_algorithms_attribute.algorithms.len);
    try std.testing.expectEqual(@as(u16, common.AlgorithmType.md5), password_algorithms_attribute.algorithms[0].type);
    try std.testing.expectEqualSlices(u8, &.{}, password_algorithms_attribute.algorithms[0].parameters);
    try std.testing.expectEqual(@as(u16, common.AlgorithmType.sha256), password_algorithms_attribute.algorithms[1].type);
    try std.testing.expectEqualSlices(u8, &.{}, password_algorithms_attribute.algorithms[1].parameters);
}

test "PASSWORD-ALGORITHM deserialization" {
    const buffer = [_]u8{
        // Header
        0x00, 0x1D,
        0x00, 0x04,
        // Type MD5
        0x00, 0x01,
        // Length
        0x00,
        0x00,
        // Empty parameters
    };

    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const password_algorithm_attribute = try common.PasswordAlgorithm.fromAttribute(attribute);

    try std.testing.expectEqual(@as(u16, common.AlgorithmType.md5), password_algorithm_attribute.algorithm.type);
    try std.testing.expectEqualSlices(u8, &.{}, password_algorithm_attribute.algorithm.parameters);
}

test "UNKNOWN-ATTRIBUTES deserialization" {
    const buffer = [_]u8{
        // Header
        0x00, 0x0A,
        0x00, 0x06,
        // Attribute 1
        0x7F, 0x00,
        // Attribute 2
        0x7F, 0x01,
        // Attribute 3
        0x7F, 0x02,
        // Padding
        0x00, 0x00,
    };

    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const unknown_attributes_attribute = try common.UnknownAttributes.fromAttribute(attribute, std.testing.allocator);
    defer std.testing.allocator.free(unknown_attributes_attribute.attribute_types);

    try std.testing.expectEqual(@as(usize, 3), unknown_attributes_attribute.attribute_types.len);
    try std.testing.expectEqual(@as(u16, 0x7F00), unknown_attributes_attribute.attribute_types[0]);
    try std.testing.expectEqual(@as(u16, 0x7F01), unknown_attributes_attribute.attribute_types[1]);
    try std.testing.expectEqual(@as(u16, 0x7F02), unknown_attributes_attribute.attribute_types[2]);
}

test "SOFTWARE deserialization" {
    const buffer = [_]u8{
        // Header
        0x80,
        0x22,
        0x00,
        0x08,
        // Value
        @as(u8, 's'),
        @as(u8, 'o'),
        @as(u8, 'f'),
        @as(u8, 't'),
        @as(u8, 'w'),
        @as(u8, 'a'),
        @as(u8, 'r'),
        @as(u8, 'e'),
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const software_attribute = try common.Software.fromAttribute(attribute);

    try std.testing.expectEqualStrings("software", software_attribute.value);
}

test "ALTERNATE-SERVER deserialization" {
    const buffer = [_]u8{
        // Header
        0x80, 0x23,
        0x00, 0x08,
        // Padding
        0x00,
        // Family type
        0x01,
        // Port
        0x01, 0x02,
        // Address
        127,  0,
        0,    1,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const alternate_server_attribute = try common.AlternateServer.fromAttribute(attribute);

    try std.testing.expectEqual(@as(u16, 0x0102), alternate_server_attribute.port);
    try std.testing.expectEqual(common.AddressFamilyType.ipv4, alternate_server_attribute.family);
    try std.testing.expectEqual(@as(u32, 0x7F000001), alternate_server_attribute.family.ipv4);
}

test "ALTERNATE-DOMAIN deserialization" {
    const buffer = [_]u8{
        // Header
        0x80,
        0x03,
        0x00,
        0x07,
        // Value
        @as(u8, 'l'),
        @as(u8, 'o'),
        @as(u8, 's'),
        @as(u8, 't'),
        @as(u8, '.'),
        @as(u8, 'i'),
        @as(u8, 'o'),
        // Padding
        0,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const alternate_domain_attribute = try common.AlternateDomain.fromAttribute(attribute);

    try std.testing.expectEqualStrings("lost.io", alternate_domain_attribute.value);
}

test "PRIORITY deserialization" {
    const buffer = [_]u8{
        // Header
        0x00, 0x24,
        0x00, 0x04,
        // Value
        0x01, 0x02,
        0x03, 0x04,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const priority_attribute = try common.Priority.fromAttribute(attribute);

    try std.testing.expectEqual(@as(u32, 0x01020304), priority_attribute.value);
}

test "USE-CANDIDATE deserialization" {
    const buffer = [_]u8{
        // Header
        0x00, 0x25,
        0x00, 0x00,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    _ = try common.UseCandidate.fromAttribute(attribute);
}

test "ICE-CONTROLLED deserialization" {
    const buffer = [_]u8{
        // Header
        0x80, 0x29,
        0x00, 0x08,
        // Value
        0x01, 0x02,
        0x03, 0x04,
        0x05, 0x06,
        0x07, 0x08,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const ice_controlled_attribute = try common.IceControlled.fromAttribute(attribute);

    try std.testing.expectEqual(@as(u64, 0x0102030405060708), ice_controlled_attribute.value);
}

test "ICE-CONTROLLING deserialization" {
    const buffer = [_]u8{
        // Header
        0x80, 0x2A,
        0x00, 0x08,
        // Value
        0x01, 0x02,
        0x03, 0x04,
        0x05, 0x06,
        0x07, 0x08,
    };
    var stream = std.io.fixedBufferStream(&buffer);
    var attribute = try readAlloc(stream.reader(), std.testing.allocator);
    defer std.testing.allocator.free(attribute.data);

    const ice_controlling_attribute = try common.IceControlling.fromAttribute(attribute);

    try std.testing.expectEqual(@as(u64, 0x0102030405060708), ice_controlling_attribute.value);
}
